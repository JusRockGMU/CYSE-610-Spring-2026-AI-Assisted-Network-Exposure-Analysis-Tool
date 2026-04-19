#!/usr/bin/env python3
"""
Flask web application for AI-Assisted Network Exposure Analysis.
Provides web interface for uploading Nmap scans and viewing results.
"""
import os
import uuid
import json
from datetime import datetime, timedelta
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_file, session
from dotenv import load_dotenv

from src.parser import NmapParser
from src.processor import DataProcessor
from src.analyzer import VulnerabilityAnalyzer
from src.reporter import ReportGenerator
from src.explainer import VulnerabilityExplainer

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'data/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'xml', 'txt', 'nmap'}

# In-memory storage for scan results (scan_id -> results)
scan_results = {}

# Cleanup old scans after 1 hour
SCAN_EXPIRY = timedelta(hours=1)


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def cleanup_old_scans():
    """Remove scan results older than SCAN_EXPIRY."""
    current_time = datetime.now()
    expired_scans = [
        scan_id for scan_id, data in scan_results.items()
        if current_time - data['timestamp'] > SCAN_EXPIRY
    ]
    for scan_id in expired_scans:
        del scan_results[scan_id]


def process_scan_file(file_path, use_ai=False):
    """Process a single scan file through the pipeline."""
    parser = NmapParser()
    processor = DataProcessor()
    analyzer = VulnerabilityAnalyzer(use_ai=use_ai)
    reporter = ReportGenerator()
    
    # Parse
    if file_path.endswith('.xml'):
        scan_data = parser.parse_xml(file_path)
    else:
        scan_data = parser.parse_text(file_path)
    
    # Process
    processed_data = processor.process(scan_data)
    
    # Analyze
    analysis_data = analyzer.analyze(processed_data)
    
    # Generate web-friendly JSON
    web_data = reporter.generate_web_json(analysis_data)
    
    return {
        'scan_data': scan_data,
        'processed_data': processed_data,
        'analysis_data': analysis_data,
        'web_data': web_data
    }


@app.route('/')
def index():
    """Home page with upload form."""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    """Handle file upload and process scans."""
    cleanup_old_scans()
    
    # Check if files were uploaded
    if 'files[]' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('files[]')
    use_ai = request.form.get('use_ai') == 'true'
    
    if not files or files[0].filename == '':
        return jsonify({'error': 'No files selected'}), 400
    
    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    scan_dir = os.path.join(app.config['UPLOAD_FOLDER'], scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    
    # Process uploaded files
    results = []
    errors = []
    
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(scan_dir, filename)
            file.save(file_path)
            
            try:
                result = process_scan_file(file_path, use_ai=use_ai)
                results.append({
                    'filename': filename,
                    'data': result
                })
            except Exception as e:
                errors.append({
                    'filename': filename,
                    'error': str(e)
                })
        else:
            errors.append({
                'filename': file.filename,
                'error': 'Invalid file type'
            })
    
    if not results:
        return jsonify({'error': 'No valid scans processed', 'details': errors}), 400
    
    # Store results
    scan_results[scan_id] = {
        'timestamp': datetime.now(),
        'results': results,
        'errors': errors,
        'use_ai': use_ai
    }
    
    return jsonify({
        'scan_id': scan_id,
        'processed': len(results),
        'errors': len(errors)
    })


@app.route('/results/<scan_id>')
def results(scan_id):
    """Display scan results."""
    if scan_id not in scan_results:
        return render_template('error.html', message='Scan not found or expired'), 404
    
    data = scan_results[scan_id]
    return render_template('results.html', scan_id=scan_id, data=data)


@app.route('/api/vulnerability/<scan_id>/<int:host_idx>/<int:vuln_idx>')
def get_vulnerability_details(scan_id, host_idx, vuln_idx):
    """Get detailed vulnerability information with AI explanation."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    data = scan_results[scan_id]
    
    try:
        # Flatten all hosts from all scans
        all_hosts = []
        for result in data['results']:
            analysis_data = result['data']['analysis_data']
            all_hosts.extend(analysis_data['hosts'])
        
        # Get the specific vulnerability
        host = all_hosts[host_idx]
        vulnerability = host['vulnerabilities'][vuln_idx]
        
        # Get AI explanation if it was pre-generated
        explanation = vulnerability.get('ai_explanation')
        
        return jsonify({
            'vulnerability': vulnerability,
            'host': {
                'ip': host['ip'],
                'hostname': host.get('hostname', ''),
                'os': host.get('os', {})
            },
            'explanation': explanation
        })
    
    except (IndexError, KeyError) as e:
        return jsonify({'error': 'Vulnerability not found'}), 404


@app.route('/api/ask/<scan_id>', methods=['POST'])
def ask_question(scan_id):
    """Answer questions about scan results using AI."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    question = request.json.get('question')
    if not question:
        return jsonify({'error': 'No question provided'}), 400
    
    data = scan_results[scan_id]
    
    # Aggregate all analysis data from all scans
    all_hosts = []
    for result in data['results']:
        analysis_data = result['data']['analysis_data']
        all_hosts.extend(analysis_data['hosts'])
    
    # Create aggregated analysis data
    aggregated_data = {
        'hosts': all_hosts,
        'summary': {
            'total_vulnerabilities': sum(len(h['vulnerabilities']) for h in all_hosts),
            'hosts_scanned': len(all_hosts)
        }
    }
    
    try:
        explainer = VulnerabilityExplainer()
        answer = explainer.answer_question(aggregated_data, question)
        
        return jsonify({
            'question': question,
            'answer': answer
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/remediation/<scan_id>/<int:host_idx>/<int:vuln_idx>', methods=['POST'])
def get_remediation(scan_id, host_idx, vuln_idx):
    """Get detailed AI-powered remediation guidance for a specific vulnerability."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    data = scan_results[scan_id]
    
    try:
        # Flatten all hosts from all scans
        all_hosts = []
        for result in data['results']:
            analysis_data = result['data']['analysis_data']
            all_hosts.extend(analysis_data['hosts'])
        
        host = all_hosts[host_idx]
        vulnerability = host['vulnerabilities'][vuln_idx]
        
        explainer = VulnerabilityExplainer()
        guidance = explainer.get_remediation_guidance(vulnerability, host)
        
        return jsonify({
            'guidance': guidance
        })
    
    except (IndexError, KeyError) as e:
        return jsonify({'error': 'Vulnerability not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/download/<scan_id>/<format>')
def download_report(scan_id, format):
    """Download report in specified format."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    if format not in ['json', 'html']:
        return jsonify({'error': 'Invalid format'}), 400
    
    data = scan_results[scan_id]
    result = data['results'][0]  # For now, handle single scan
    analysis_data = result['data']['analysis_data']
    
    # Generate report files
    reporter = ReportGenerator()
    output_dir = os.path.join(app.config['UPLOAD_FOLDER'], scan_id, 'reports')
    os.makedirs(output_dir, exist_ok=True)
    
    report_paths = reporter.generate(analysis_data, output_dir)
    
    if format == 'json':
        return send_file(report_paths['json'], as_attachment=True, download_name=f'vulnerability_report_{scan_id}.json')
    else:
        return send_file(report_paths['html'], as_attachment=True, download_name=f'vulnerability_report_{scan_id}.html')


@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'active_scans': len(scan_results)})


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('data/reports', exist_ok=True)
    
    # Run Flask app on port 8080 (5000 often used by macOS AirPlay)
    app.run(debug=True, host='0.0.0.0', port=8080)
