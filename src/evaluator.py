import json
from typing import Dict, List, Set
import os


class VulnerabilityEvaluator:
    """Evaluate analysis results against baseline vulnerability data."""
    
    def __init__(self):
        self.baseline_data = {}
        self.evaluation_results = {}
    
    def load_baseline(self, baseline_path: str) -> Dict:
        """
        Load baseline vulnerability data.
        
        Args:
            baseline_path: Path to baseline JSON file
            
        Returns:
            Baseline data dictionary
        """
        if not os.path.exists(baseline_path):
            raise FileNotFoundError(f"Baseline file not found: {baseline_path}")
        
        with open(baseline_path, 'r') as f:
            self.baseline_data = json.load(f)
        
        return self.baseline_data
    
    def evaluate(self, analysis_data: Dict, baseline_data: Dict = None) -> Dict:
        """
        Evaluate analysis results against baseline.
        
        Args:
            analysis_data: Analysis results to evaluate
            baseline_data: Baseline vulnerability data (optional if already loaded)
            
        Returns:
            Evaluation metrics and results
        """
        if baseline_data:
            self.baseline_data = baseline_data
        
        if not self.baseline_data:
            raise ValueError("No baseline data available. Load baseline first.")
        
        detected_vulns = self._extract_detected_vulnerabilities(analysis_data)
        baseline_vulns = self._extract_baseline_vulnerabilities(self.baseline_data)
        
        true_positives = detected_vulns & baseline_vulns
        false_positives = detected_vulns - baseline_vulns
        false_negatives = baseline_vulns - detected_vulns
        
        precision = len(true_positives) / len(detected_vulns) if detected_vulns else 0
        recall = len(true_positives) / len(baseline_vulns) if baseline_vulns else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        evaluation = {
            'metrics': {
                'precision': round(precision, 3),
                'recall': round(recall, 3),
                'f1_score': round(f1_score, 3),
                'true_positives': len(true_positives),
                'false_positives': len(false_positives),
                'false_negatives': len(false_negatives),
                'total_detected': len(detected_vulns),
                'total_baseline': len(baseline_vulns)
            },
            'details': {
                'true_positives': list(true_positives),
                'false_positives': list(false_positives),
                'false_negatives': list(false_negatives)
            }
        }
        
        self.evaluation_results = evaluation
        return evaluation
    
    def _extract_detected_vulnerabilities(self, analysis_data: Dict) -> Set[str]:
        """Extract set of detected vulnerabilities."""
        detected = set()
        
        for host in analysis_data.get('hosts', []):
            ip = host.get('ip', 'unknown')
            for vuln in host.get('vulnerabilities', []):
                port = vuln.get('port', 0)
                service = vuln.get('service', 'unknown')
                vuln_key = f"{ip}:{port}:{service}"
                detected.add(vuln_key)
        
        return detected
    
    def _extract_baseline_vulnerabilities(self, baseline_data: Dict) -> Set[str]:
        """Extract set of baseline vulnerabilities."""
        baseline = set()
        
        for host in baseline_data.get('hosts', []):
            ip = host.get('ip', 'unknown')
            for vuln in host.get('vulnerabilities', []):
                port = vuln.get('port', 0)
                service = vuln.get('service', 'unknown')
                vuln_key = f"{ip}:{port}:{service}"
                baseline.add(vuln_key)
        
        return baseline
    
    def generate_report(self) -> str:
        """Generate evaluation report as formatted string."""
        if not self.evaluation_results:
            return "No evaluation results available."
        
        metrics = self.evaluation_results['metrics']
        
        report = f"""
╔══════════════════════════════════════════════════════════╗
║         VULNERABILITY DETECTION EVALUATION               ║
╚══════════════════════════════════════════════════════════╝

PERFORMANCE METRICS:
  Precision:        {metrics['precision']:.1%}
  Recall:           {metrics['recall']:.1%}
  F1 Score:         {metrics['f1_score']:.3f}

DETECTION SUMMARY:
  True Positives:   {metrics['true_positives']}
  False Positives:  {metrics['false_positives']}
  False Negatives:  {metrics['false_negatives']}
  
  Total Detected:   {metrics['total_detected']}
  Total Baseline:   {metrics['total_baseline']}

INTERPRETATION:
  - Precision: {self._interpret_precision(metrics['precision'])}
  - Recall:    {self._interpret_recall(metrics['recall'])}
  - Overall:   {self._interpret_overall(metrics['f1_score'])}
"""
        
        return report
    
    def _interpret_precision(self, precision: float) -> str:
        """Interpret precision score."""
        if precision >= 0.9:
            return "Excellent - Very few false alarms"
        elif precision >= 0.7:
            return "Good - Acceptable false positive rate"
        elif precision >= 0.5:
            return "Fair - Consider refining detection rules"
        else:
            return "Poor - High false positive rate"
    
    def _interpret_recall(self, recall: float) -> str:
        """Interpret recall score."""
        if recall >= 0.9:
            return "Excellent - Catching nearly all vulnerabilities"
        elif recall >= 0.7:
            return "Good - Detecting most vulnerabilities"
        elif recall >= 0.5:
            return "Fair - Missing some vulnerabilities"
        else:
            return "Poor - Missing many vulnerabilities"
    
    def _interpret_overall(self, f1: float) -> str:
        """Interpret overall F1 score."""
        if f1 >= 0.8:
            return "Excellent detection performance"
        elif f1 >= 0.6:
            return "Good detection performance"
        elif f1 >= 0.4:
            return "Fair detection performance"
        else:
            return "Needs improvement"
    
    def save_evaluation(self, output_path: str):
        """Save evaluation results to JSON file."""
        if not self.evaluation_results:
            raise ValueError("No evaluation results to save.")
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.evaluation_results, f, indent=2)
