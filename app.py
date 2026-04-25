#!/usr/bin/env python3
"""
Flask web application for Network Exposure Analysis.
Provides web interface for uploading Nmap scans and viewing results.
"""
import os
import uuid
import json
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, send_file, session, redirect
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

# Progress tracking (scan_id -> progress_data)
# Enhanced to include: step, percent, status (AI/NVD/Processing), timestamps, step_times
scan_progress = {}

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


def process_scan_file(file_path, use_ai=False, deep_analysis=True, progress_callback=None):
    """Process a single scan file through the pipeline."""
    
    print("\n" + "🚀"*40)
    print(f"APP.PY: process_scan_file() called for: {file_path}")
    print("🚀"*40 + "\n")
    
    def update_progress(step, percent, status='Processing', extra_data=None):
        """Update progress if callback provided."""
        if progress_callback:
            progress_callback(step, percent, status, extra_data)
    
    parser = NmapParser()
    processor = DataProcessor()
    analyzer = VulnerabilityAnalyzer(use_ai=use_ai, deep_analysis=deep_analysis)
    reporter = ReportGenerator()
    
    # Parse
    update_progress('Parsing scan file', 20, 'Processing')
    if file_path.endswith('.xml'):
        scan_data = parser.parse_xml(file_path)
    else:
        scan_data = parser.parse_text(file_path)
    
    # Process
    update_progress('Processing scan data', 40, 'Processing')
    processed_data = processor.process(scan_data)
    
    # Analyze (this is the slow part - NVD API calls)
    # Pass progress callback to analyzer for detailed updates
    update_progress('Starting vulnerability analysis', 50, 'Analyzing')
    analysis_data = analyzer.analyze(processed_data, progress_callback=update_progress)
    
    # Generate web-friendly JSON
    update_progress('Generating results', 90, 'Finalizing')
    web_data = reporter.generate_web_json(analysis_data)
    
    update_progress('Complete', 100, 'Complete')
    
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


@app.route('/monitor')
def monitor():
    """Live scan monitor page."""
    scan_id = request.args.get('scan_id')
    
    # If no scan_id provided, try to find an active scan
    if not scan_id:
        # Look for running scans (exclude cancelled)
        for sid, progress in scan_progress.items():
            status = progress.get('status')
            percent = progress.get('percent', 0)
            # Only show if running (not cancelled, not complete)
            if status != 'Cancelled' and percent < 100:
                scan_id = sid
                break
    
    return render_template('monitor.html', scan_id=scan_id)


@app.route('/summary')
def summary():
    """Summary page - shows most recent completed scan or allows selection."""
    # Find most recent completed scan
    most_recent_scan_id = None
    most_recent_time = None
    
    for scan_id, result in scan_results.items():
        timestamp = result.get('timestamp')
        if timestamp and (most_recent_time is None or timestamp > most_recent_time):
            most_recent_time = timestamp
            most_recent_scan_id = scan_id
    
    # If we found a completed scan, redirect to its results
    if most_recent_scan_id:
        return redirect(f'/results/{most_recent_scan_id}')
    
    # Otherwise, redirect to history to select a scan
    return redirect('/history')


@app.route('/history')
def history():
    """Scan history page."""
    return render_template('history.html')


@app.route('/api/scans')
def get_scans():
    """Get all scans with their status."""
    scans = []
    
    # Get all scans from progress and results
    for scan_id in set(list(scan_progress.keys()) + list(scan_results.keys())):
        scan_info = {
            'scan_id': scan_id,
            'timestamp': None,
            'status': 'Unknown',
            'file_count': 0,
            'duration': None,
            'vuln_count': 0
        }
        
        # Check if scan is in progress
        if scan_id in scan_progress:
            progress = scan_progress[scan_id]
            scan_info['step'] = progress.get('step', 'Unknown')
            scan_info['percent'] = progress.get('percent', 0)
            scan_info['file_count'] = progress.get('total_files', 1)
            scan_info['filenames'] = progress.get('filenames', [])
            
            # Get timestamp from start_time
            start_time = progress.get('start_time')
            if start_time:
                scan_info['timestamp'] = start_time.isoformat()
            
            # Check for explicit status first (e.g., 'Cancelled')
            explicit_status = progress.get('status')
            if explicit_status == 'Cancelled':
                scan_info['status'] = 'cancelled'
            elif progress.get('percent', 0) >= 100:
                scan_info['status'] = 'complete'
            else:
                scan_info['status'] = 'running'
            
            elapsed = progress.get('elapsed_time', 0)
            scan_info['duration'] = f"{elapsed:.1f}s"
        
        # Check if scan has results
        if scan_id in scan_results:
            result = scan_results[scan_id]
            scan_info['timestamp'] = result.get('timestamp', datetime.now()).isoformat()
            scan_info['status'] = 'Complete'
            
            # Count vulnerabilities
            total_vulns = 0
            if 'results' in result:
                for file_result in result['results']:
                    if 'data' in file_result and 'web_data' in file_result['data']:
                        for host in file_result['data']['web_data'].get('hosts', []):
                            total_vulns += len(host.get('vulnerabilities', []))
            
            scan_info['vuln_count'] = total_vulns
            
            if 'timing' in result:
                total_time = result['timing'].get('total_time', 0)
                scan_info['duration'] = f"{total_time:.1f}s"
        
        scans.append(scan_info)
    
    # Sort by timestamp (newest first)
    scans.sort(key=lambda x: x['timestamp'] or '', reverse=True)
    
    return jsonify({'scans': scans})


@app.route('/api/scans/<scan_id>/cancel', methods=['POST'])
def cancel_scan(scan_id):
    """Cancel a running scan."""
    if scan_id in scan_progress:
        # Mark as cancelled
        scan_progress[scan_id]['percent'] = 100
        scan_progress[scan_id]['step'] = 'Cancelled by user'
        scan_progress[scan_id]['status'] = 'Cancelled'
        return jsonify({'success': True})
    return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan from history and all associated data."""
    deleted = False
    
    # Remove from progress tracking
    if scan_id in scan_progress:
        del scan_progress[scan_id]
        deleted = True
    
    # Remove from results
    if scan_id in scan_results:
        del scan_results[scan_id]
        deleted = True
    
    # Delete generated report file if it exists
    report_path = Path('reports') / f'vulnerability_report_{scan_id}.html'
    if report_path.exists():
        try:
            report_path.unlink()
            deleted = True
        except Exception as e:
            print(f"Failed to delete report file: {e}")
    
    if deleted:
        return jsonify({'success': True})
    return jsonify({'error': 'Scan not found'}), 404


def process_files_async(scan_id, file_paths, use_ai, deep_analysis=True):
    """Process files asynchronously in background thread."""
    results = []
    errors = []
    
    def update_file_progress(step, percent, status='Processing', extra_data=None):
        """Update progress for current file with detailed status and timing."""
        if scan_id not in scan_progress:
            return
            
        file_idx = scan_progress[scan_id]['current_file']
        total_files = scan_progress[scan_id]['total_files']
        
        # Calculate overall progress based on file progress
        base_progress = (file_idx / total_files) * 80  # 0-80% for all files
        file_progress = (percent / 100) * (80 / total_files)  # This file's contribution
        overall_progress = 10 + base_progress + file_progress  # Start at 10%
        
        current_time = datetime.now()
        last_update = scan_progress[scan_id].get('last_update', current_time)
        step_duration = (current_time - last_update).total_seconds()
        
        # Track step times for display
        if 'step_times' not in scan_progress[scan_id]:
            scan_progress[scan_id]['step_times'] = []
        
        # Add step time if progress increased
        if int(overall_progress) > scan_progress[scan_id].get('percent', 0):
            scan_progress[scan_id]['step_times'].append({
                'percent': int(overall_progress),
                'duration': round(step_duration, 2),
                'step': step,
                'status': status
            })
        
        # Handle CVE data updates
        if extra_data and 'port' in extra_data and 'cves' in extra_data:
            port = str(extra_data['port'])
            cves = extra_data['cves']
            stage = extra_data.get('stage', 'found')
            
            print(f"📊 CVE UPDATE: Port {port}, Stage {stage}, CVEs: {cves}, Pass: {extra_data.get('pass', 'N/A')}")
            
            if port not in scan_progress[scan_id]['port_cves']:
                scan_progress[scan_id]['port_cves'][port] = {'found': [], 'final': [], 'pass': 0}
            
            if stage == 'found':
                scan_progress[scan_id]['port_cves'][port]['found'] = cves
                # Store the pass number if provided
                if 'pass' in extra_data:
                    scan_progress[scan_id]['port_cves'][port]['pass'] = extra_data['pass']
                print(f"✅ Stored {len(cves)} found CVEs for port {port} (Pass {extra_data.get('pass', 'N/A')})")
            elif stage == 'final':
                scan_progress[scan_id]['port_cves'][port]['final'] = cves
                print(f"✅ Stored {len(cves)} final CVEs for port {port}")
        
        scan_progress[scan_id].update({
            'step': f'{step} ({file_idx + 1}/{total_files})',
            'percent': int(overall_progress),
            'status': status,
            'current_file': file_idx,
            'total_files': total_files,
            'last_update': current_time,
            'elapsed_time': (current_time - scan_progress[scan_id]['start_time']).total_seconds()
        })
    
    try:
        for idx, (filename, file_path) in enumerate(file_paths):
            scan_progress[scan_id]['current_file'] = idx
            
            try:
                result = process_scan_file(file_path, use_ai=use_ai, deep_analysis=deep_analysis, progress_callback=update_file_progress)
                results.append({
                    'filename': filename,
                    'data': result
                })
            except Exception as e:
                errors.append({
                    'filename': filename,
                    'error': str(e)
                })
        
        # Store results with timing data
        end_time = datetime.now()
        total_time = (end_time - scan_progress[scan_id]['start_time']).total_seconds()
        
        scan_results[scan_id] = {
            'timestamp': datetime.now(),
            'results': results,
            'errors': errors,
            'use_ai': use_ai,
            'timing': {
                'total_time': total_time,
                'step_times': scan_progress[scan_id].get('step_times', []),
                'total_files': scan_progress[scan_id].get('total_files', 0)
            }
        }
        
        scan_progress[scan_id].update({
            'step': 'Complete',
            'percent': 100,
            'status': 'Complete',
            'elapsed_time': total_time
        })
        
    except Exception as e:
        scan_progress[scan_id].update({
            'step': f'Error: {str(e)}',
            'percent': 0,
            'status': 'Error'
        })


@app.route('/upload', methods=['POST'])
def upload():
    """Handle file upload and start async processing."""
    cleanup_old_scans()
    
    # Check if files were uploaded
    if 'files[]' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('files[]')
    use_ai = request.form.get('use_ai') == 'true'
    deep_analysis = request.form.get('deep_analysis') == 'true'
    
    if not files or files[0].filename == '':
        return jsonify({'error': 'No files selected'}), 400
    
    # Create upload directory
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    scan_dir = os.path.join(app.config['UPLOAD_FOLDER'], scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    
    # Initialize progress tracking with timing
    scan_progress[scan_id] = {
        'step': 'Uploading files',
        'percent': 5,
        'status': 'Uploading',
        'current_file': 0,
        'total_files': 0,
        'start_time': datetime.now(),
        'last_update': datetime.now(),
        'elapsed_time': 0,
        'step_times': [],
        'port_cves': {},  # Store CVE IDs per port for live monitoring
        'deep_analysis': deep_analysis,  # Track if multi-pass analysis is enabled
        'use_ai': use_ai
    }
    
    # Save files and collect paths
    file_paths = []
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(scan_dir, filename)
            file.save(file_path)
            file_paths.append((filename, file_path))
    
    if not file_paths:
        scan_progress[scan_id] = {'step': 'Error: No valid files', 'percent': 0}
        return jsonify({'error': 'No valid files uploaded'}), 400
    
    # Extract all ports from Nmap files to pre-build port cards
    all_ports = set()
    for filename, file_path in file_paths:
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    if port_id:
                        all_ports.add(port_id)
        except Exception as e:
            print(f"⚠️  Could not extract ports from {filename}: {e}")
    
    discovered_ports = sorted(all_ports, key=int) if all_ports else []
    print(f"📋 Pre-discovered {len(discovered_ports)} ports: {discovered_ports}")
    
    # Update progress
    scan_progress[scan_id].update({
        'step': 'Starting analysis',
        'percent': 10,
        'status': 'Initializing',
        'current_file': 0,
        'total_files': len(file_paths),
        'filenames': [filename for filename, _ in file_paths],
        'discovered_ports': discovered_ports  # Send all ports to frontend
    })
    
    # Start async processing
    thread = threading.Thread(
        target=process_files_async,
        args=(scan_id, file_paths, use_ai, deep_analysis),
        daemon=True
    )
    thread.start()
    
    # Return immediately with scan ID
    return jsonify({
        'scan_id': scan_id,
        'total_files': len(file_paths)
    })


@app.route('/api/results/<scan_id>')
def api_results(scan_id):
    """API endpoint to get scan results data."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])


@app.route('/results/<scan_id>')
def results(scan_id):
    """Display scan results."""
    if scan_id not in scan_results:
        return "Scan not found or still processing", 404
    
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
        
        # Check if this is a filtered vulnerability (index >= 1000)
        if vuln_idx >= 1000:
            # Filtered vulnerability - subtract offset and look in filtered_vulnerabilities
            actual_idx = vuln_idx - 1000
            vulnerability = host.get('filtered_vulnerabilities', [])[actual_idx]
        else:
            # Regular vulnerability
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


@app.route('/api/progress/<scan_id>')
def get_progress(scan_id):
    """Get current progress for a scan with timing information."""
    if scan_id in scan_progress:
        progress_data = scan_progress[scan_id].copy()
        
        # Convert datetime objects to serializable format
        if 'start_time' in progress_data:
            del progress_data['start_time']
        if 'last_update' in progress_data:
            del progress_data['last_update']
        
        # Round elapsed time
        if 'elapsed_time' in progress_data:
            progress_data['elapsed_time'] = round(progress_data['elapsed_time'], 2)
        
        return jsonify(progress_data)
    return jsonify({'step': 'Unknown', 'percent': 0, 'status': 'Unknown'})


@app.route('/status')
def status():
    """System status page."""
    return render_template('status.html')


@app.route('/health')
def health():
    """Health check endpoint with detailed system information."""
    import sys
    import flask
    
    # Check NVD availability
    nvd_available = True
    try:
        from src.nvd_client import NVDClient
        nvd_client = NVDClient()
        nvd_available = True
    except Exception:
        nvd_available = False
    
    # Check AI availability
    ai_available = bool(os.getenv('ANTHROPIC_API_KEY'))
    
    # Count scans
    total_scans = len(set(list(scan_progress.keys()) + list(scan_results.keys())))
    running_scans = sum(1 for scan_id in scan_progress if scan_progress[scan_id].get('percent', 0) < 100)
    
    return jsonify({
        'status': 'healthy' if (nvd_available or ai_available) else 'degraded',
        'timestamp': datetime.now().isoformat(),
        'nvd_available': nvd_available,
        'ai_available': ai_available,
        'total_scans': total_scans,
        'running_scans': running_scans,
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'flask_version': flask.__version__
    })


if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('data/reports', exist_ok=True)
    
    # Run Flask app on port 8080 (5000 often used by macOS AirPlay)
    app.run(debug=True, host='0.0.0.0', port=8080)
