#!/usr/bin/env python3
"""
analysis_engine.py - Analysis and Correlation Engine for GitLab Security Audit System

This module provides comprehensive analysis and correlation of security findings from
multiple detection tools. It handles deduplication, risk classification, and generates
actionable intelligence from raw scanner output.
"""

import hashlib
import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

try:
    from .risk_classifier import RiskClassifier
    from .detection_config import BASE_DIR, REPORTS_DIR
except ImportError:
    from risk_classifier import RiskClassifier
    from detection_config import BASE_DIR, REPORTS_DIR

# Configure logging
logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Core analysis engine that correlates findings from multiple security tools.

    This engine processes standardized output from the DetectionEngine to:
    - Normalize findings from different tools into consistent format
    - Eliminate duplicate findings using signature-based deduplication
    - Calculate risk scores and classify risk levels
    - Generate comprehensive analysis summaries with statistics
    - Support business context integration for enhanced risk assessment
    """

    def __init__(self) -> None:
        """Initialize the analysis engine with risk classifier."""
        self.risk_classifier = RiskClassifier()
        self.reports_dir = Path(REPORTS_DIR)
        self.reports_dir.mkdir(exist_ok=True)

        logger.info("Analysis engine initialized")

    def correlate_findings(self, detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate findings from multiple security tools.

        Args:
            detection_results: Results from DetectionEngine.scan_project()

        Returns:
            Dictionary containing correlated and analyzed findings
        """
        logger.info("Starting correlation analysis of detection results")

        if detection_results.get('status') != 'success':
            return {
                'status': 'error',
                'error': f"Invalid detection results: {detection_results.get('error', 'Unknown error')}",
                'correlated': [],
                'analysis_summary': {}
            }

        # Extract tool results
        tool_results = detection_results.get('results', {})
        if not tool_results:
            return {
                'status': 'success',
                'correlated': [],
                'analysis_summary': self._generate_empty_summary()
            }

        # Normalize findings from all tools
        normalized_findings = []
        for tool_name, tool_result in tool_results.items():
            if tool_result.get('status') == 'success':
                findings = tool_result.get('findings', [])
                for finding in findings:
                    normalized = self._normalize_finding(finding, tool_name)
                    if normalized:
                        normalized_findings.append(normalized)

        logger.info("Normalized %d findings from %d tools",
                   len(normalized_findings), len(tool_results))

        # Deduplicate findings using signature-based approach
        unique_findings = self._deduplicate_findings(normalized_findings)
        logger.info("After deduplication: %d unique findings", len(unique_findings))

        # Classify risks for all findings
        classified_findings = self.classify_risks(unique_findings)

        # Group by risk level for summary
        risk_groups = self._group_by_risk_level(classified_findings)

        # Generate comprehensive analysis summary
        analysis_summary = self._generate_analysis_summary(
            classified_findings, risk_groups, detection_results
        )

        return {
            'status': 'success',
            'correlated': classified_findings,
            'risk_groups': risk_groups,
            'analysis_summary': analysis_summary,
            'correlation_metadata': {
                'total_raw_findings': len(normalized_findings),
                'unique_findings': len(unique_findings),
                'deduplication_ratio': (len(normalized_findings) - len(unique_findings)) / max(len(normalized_findings), 1),
                'tools_analyzed': list(tool_results.keys()),
                'analysis_timestamp': datetime.now().isoformat()
            }
        }

    def _normalize_finding(self, finding: Dict[str, Any], tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Normalize a finding from any tool into consistent format.

        Args:
            finding: Raw finding from tool output
            tool_name: Name of the tool that generated the finding

        Returns:
            Normalized finding dictionary or None if invalid
        """
        try:
            if tool_name == 'gitleaks':
                return self._normalize_gitleaks_finding(finding, tool_name)
            elif tool_name == 'semgrep':
                return self._normalize_semgrep_finding(finding, tool_name)
            elif tool_name == 'trufflehog':
                return self._normalize_trufflehog_finding(finding, tool_name)
            else:
                logger.warning("Unknown tool: %s", tool_name)
                return None

        except Exception as e:
            logger.error("Error normalizing finding from %s: %s", tool_name, e)
            return None

    def _normalize_gitleaks_finding(self, finding: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
        """Normalize gitleaks finding format."""
        secret = finding.get('Secret', '').strip()
        file_path = finding.get('File', '')
        rule_id = finding.get('RuleID', '')

        # Classify secret type from rule ID and tags
        tags = finding.get('Tags', [])
        secret_type = self._classify_secret_type_from_gitleaks(rule_id, tags)

        return {
            'id': self._generate_finding_id(),
            'source_tool': tool_name,
            'tools_detected': [tool_name],
            'secret_type': secret_type,
            'secret_value': secret[:50] + '...' if len(secret) > 50 else secret,  # Truncate for safety
            'file_path': file_path,
            'line_number': finding.get('StartLine'),
            'column_number': finding.get('StartColumn'),
            'description': finding.get('Description', ''),
            'rule_id': rule_id,
            'entropy': finding.get('Entropy'),
            'tags': tags,
            'signature': self._generate_finding_signature(secret, file_path, rule_id),
            'raw_finding': finding
        }

    def _normalize_semgrep_finding(self, finding: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
        """Normalize semgrep finding format."""
        message = finding.get('message', '')
        file_path = finding.get('path', '')
        rule_id = finding.get('check_id', '')

        # Extract secret-like content from message or extra
        secret_value = finding.get('extra', {}).get('message', message)
        secret_type = self._classify_secret_type_from_semgrep(rule_id, message)

        return {
            'id': self._generate_finding_id(),
            'source_tool': tool_name,
            'tools_detected': [tool_name],
            'secret_type': secret_type,
            'secret_value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
            'file_path': file_path,
            'line_number': finding.get('start', {}).get('line'),
            'column_number': finding.get('start', {}).get('col'),
            'description': message,
            'rule_id': rule_id,
            'severity': finding.get('extra', {}).get('severity', 'INFO'),
            'signature': self._generate_finding_signature(secret_value, file_path, rule_id),
            'raw_finding': finding
        }

    def _normalize_trufflehog_finding(self, finding: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
        """Normalize trufflehog finding format."""
        detector_name = finding.get('DetectorName', '')
        raw_secret = finding.get('Raw', '')
        source_metadata = finding.get('SourceMetadata', {})
        file_path = source_metadata.get('Data', {}).get('Filesystem', {}).get('file', '')

        # Get verification status
        verified = finding.get('Verified', False)

        return {
            'id': self._generate_finding_id(),
            'source_tool': tool_name,
            'tools_detected': [tool_name],
            'secret_type': detector_name.lower(),
            'secret_value': raw_secret[:50] + '...' if len(raw_secret) > 50 else raw_secret,
            'file_path': file_path,
            'line_number': source_metadata.get('Data', {}).get('Filesystem', {}).get('line'),
            'description': f"{detector_name} credential found",
            'detector_name': detector_name,
            'verified': verified,
            'signature': self._generate_finding_signature(raw_secret, file_path, detector_name),
            'raw_finding': finding
        }

    def _classify_secret_type_from_gitleaks(self, rule_id: str, tags: List[str]) -> str:
        """Classify secret type from gitleaks rule ID and tags."""
        rule_id = rule_id.lower()

        # Check tags first
        for tag in tags:
            tag = tag.lower()
            if any(pattern in tag for pattern in ['aws', 'amazon']):
                return 'aws'
            elif any(pattern in tag for pattern in ['db', 'database', 'mysql', 'postgres']):
                return 'database'
            elif 'ssh' in tag:
                return 'ssh_key'
            elif 'jwt' in tag:
                return 'jwt'

        # Check rule ID patterns
        if any(pattern in rule_id for pattern in ['aws', 'amazon']):
            return 'aws'
        elif any(pattern in rule_id for pattern in ['database', 'mysql', 'postgres', 'mongodb']):
            return 'database'
        elif any(pattern in rule_id for pattern in ['ssh', 'private-key']):
            return 'ssh_key'
        elif 'jwt' in rule_id:
            return 'jwt'
        elif 'api' in rule_id:
            return 'api_key'

        return 'generic'

    def _classify_secret_type_from_semgrep(self, rule_id: str, message: str) -> str:
        """Classify secret type from semgrep rule ID and message."""
        text = (rule_id + ' ' + message).lower()

        if any(pattern in text for pattern in ['aws', 'amazon']):
            return 'aws'
        elif any(pattern in text for pattern in ['database', 'mysql', 'postgres', 'mongodb']):
            return 'database'
        elif any(pattern in text for pattern in ['ssh', 'private', 'key']):
            return 'ssh_key'
        elif 'jwt' in text:
            return 'jwt'
        elif any(pattern in text for pattern in ['api', 'token']):
            return 'api_key'

        return 'generic'

    def _generate_finding_signature(self, secret: str, file_path: str, identifier: str) -> str:
        """Generate unique signature for finding deduplication."""
        # Create signature from secret content, file path, and rule/detector identifier
        signature_data = f"{secret[:20]}{file_path}{identifier}".lower()
        return hashlib.sha256(signature_data.encode()).hexdigest()[:16]

    def _generate_finding_id(self) -> str:
        """Generate unique ID for finding."""
        timestamp = datetime.now().isoformat()
        return hashlib.sha256(timestamp.encode()).hexdigest()[:12]

    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings using signature-based deduplication.

        When multiple tools find the same secret, merge them into a single finding
        with enhanced tool consensus information.
        """
        signature_groups = defaultdict(list)

        # Group findings by signature
        for finding in findings:
            signature = finding['signature']
            signature_groups[signature].append(finding)

        unique_findings = []

        for signature, group in signature_groups.items():
            if len(group) == 1:
                # Single finding, no deduplication needed
                unique_findings.append(group[0])
            else:
                # Multiple tools found the same secret - merge them
                merged = self._merge_duplicate_findings(group)
                unique_findings.append(merged)
                logger.debug("Merged %d duplicate findings with signature %s",
                           len(group), signature)

        return unique_findings

    def _merge_duplicate_findings(self, duplicate_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge duplicate findings from multiple tools into single enhanced finding.

        Args:
            duplicate_findings: List of findings with same signature

        Returns:
            Merged finding with tool consensus information
        """
        # Use the first finding as base
        merged = duplicate_findings[0].copy()

        # Collect all tools that detected this finding
        all_tools = set()
        all_raw_findings = []

        for finding in duplicate_findings:
            all_tools.update(finding['tools_detected'])
            all_raw_findings.append({
                'tool': finding['source_tool'],
                'raw_finding': finding['raw_finding']
            })

        # Update merged finding with consensus information
        merged.update({
            'tools_detected': list(all_tools),
            'tool_consensus': len(all_tools),
            'description': f"Secret detected by {len(all_tools)} tool(s): {', '.join(sorted(all_tools))}",
            'all_raw_findings': all_raw_findings
        })

        return merged

    def classify_risks(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Classify risk levels for all findings.

        Args:
            findings: List of normalized findings

        Returns:
            List of findings with risk classification added
        """
        classified_findings = []

        for finding in findings:
            # Calculate risk score using the risk classifier
            risk_score = self.risk_classifier.calculate_risk_score(finding)
            risk_level = self.risk_classifier.classify_risk_level(risk_score)

            # Add risk information to finding
            enhanced_finding = finding.copy()
            enhanced_finding.update({
                'risk_score': risk_score,
                'risk_level': risk_level
            })

            classified_findings.append(enhanced_finding)

        return classified_findings

    def _group_by_risk_level(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by risk level."""
        risk_groups = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': []
        }

        for finding in findings:
            risk_level = finding.get('risk_level', 'INFO')
            risk_groups[risk_level].append(finding)

        return risk_groups

    def _generate_analysis_summary(self, findings: List[Dict[str, Any]],
                                 risk_groups: Dict[str, List],
                                 detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive analysis summary."""
        scan_info = detection_results.get('scan_info', {})

        # Risk statistics
        risk_stats = self.risk_classifier.get_risk_statistics(findings)

        # Tool effectiveness analysis
        tool_stats = self._analyze_tool_effectiveness(findings)

        # File path analysis
        file_stats = self._analyze_file_patterns(findings)

        # Business impact assessment
        business_impact = self._assess_business_impact(risk_groups)

        return {
            'scan_metadata': {
                'project_path': scan_info.get('project_path'),
                'scan_duration': scan_info.get('scan_duration'),
                'tools_used': scan_info.get('tools_successful', []),
                'analysis_timestamp': datetime.now().isoformat()
            },
            'risk_statistics': risk_stats,
            'tool_effectiveness': tool_stats,
            'file_analysis': file_stats,
            'business_impact': business_impact,
            'recommendations': self._generate_recommendations(risk_groups, file_stats)
        }

    def _analyze_tool_effectiveness(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze effectiveness of different security tools."""
        tool_findings = defaultdict(int)
        tool_consensus = defaultdict(int)

        for finding in findings:
            tools = finding.get('tools_detected', [])
            for tool in tools:
                tool_findings[tool] += 1

            if len(tools) > 1:
                for tool in tools:
                    tool_consensus[tool] += 1

        return {
            'findings_per_tool': dict(tool_findings),
            'consensus_findings': dict(tool_consensus),
            'tool_ranking': sorted(tool_findings.items(), key=lambda x: x[1], reverse=True)
        }

    def _analyze_file_patterns(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze file path patterns in findings."""
        file_counts = defaultdict(int)
        directory_counts = defaultdict(int)
        extension_counts = defaultdict(int)

        for finding in findings:
            file_path = finding.get('file_path', '')
            if file_path:
                file_counts[file_path] += 1

                path_obj = Path(file_path)
                directory = str(path_obj.parent)
                directory_counts[directory] += 1

                extension = path_obj.suffix.lower()
                if extension:
                    extension_counts[extension] += 1

        return {
            'most_affected_files': dict(sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'most_affected_directories': dict(sorted(directory_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
            'file_types': dict(sorted(extension_counts.items(), key=lambda x: x[1], reverse=True))
        }

    def _assess_business_impact(self, risk_groups: Dict[str, List]) -> Dict[str, Any]:
        """Assess business impact of security findings."""
        critical_count = len(risk_groups.get('CRITICAL', []))
        high_count = len(risk_groups.get('HIGH', []))

        if critical_count > 0:
            impact_level = 'CRITICAL'
            impact_description = f"{critical_count} critical security issues pose immediate threat to business operations"
        elif high_count > 0:
            impact_level = 'HIGH'
            impact_description = f"{high_count} high-risk issues could lead to data breaches or compliance violations"
        elif len(risk_groups.get('MEDIUM', [])) > 0:
            impact_level = 'MEDIUM'
            impact_description = "Medium-risk issues present manageable security concerns"
        else:
            impact_level = 'LOW'
            impact_description = "Only low-risk or informational security findings"

        return {
            'impact_level': impact_level,
            'impact_description': impact_description,
            'immediate_action_required': critical_count > 0 or high_count >= 5,
            'compliance_risk': critical_count > 0 or high_count > 0
        }

    def _generate_recommendations(self, risk_groups: Dict[str, List],
                                file_stats: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis."""
        recommendations = []

        critical_count = len(risk_groups.get('CRITICAL', []))
        high_count = len(risk_groups.get('HIGH', []))

        if critical_count > 0:
            recommendations.append(f"IMMEDIATE ACTION: Address {critical_count} critical security issues before deployment")

        if high_count > 0:
            recommendations.append(f"HIGH PRIORITY: Remediate {high_count} high-risk findings within 24-48 hours")

        # File-specific recommendations
        affected_files = file_stats.get('most_affected_files', {})
        if '.env' in ' '.join(affected_files.keys()).lower():
            recommendations.append("Review and secure .env files - consider using environment variable injection")

        if any('config' in path.lower() for path in affected_files.keys()):
            recommendations.append("Audit configuration files for hardcoded secrets - implement configuration management")

        # Tool-specific recommendations
        medium_count = len(risk_groups.get('MEDIUM', []))
        if medium_count > 10:
            recommendations.append("Consider implementing pre-commit hooks to catch secrets before they enter the repository")

        if not recommendations:
            recommendations.append("Continue regular security scans and maintain current security practices")

        return recommendations

    def _generate_empty_summary(self) -> Dict[str, Any]:
        """Generate empty analysis summary when no findings exist."""
        return {
            'risk_statistics': {
                'total_findings': 0,
                'risk_distribution': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
                'risk_summary': 'No security findings detected'
            },
            'recommendations': ['Continue regular security monitoring']
        }

    def save_analysis(self, analysis_results: Dict[str, Any],
                     output_file: Optional[str] = None) -> str:
        """Save analysis results to JSON file."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.reports_dir / f"security_analysis_{timestamp}.json"
        else:
            output_file = Path(output_file)

        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(analysis_results, f, indent=2, default=str)

        logger.info("Analysis results saved to %s", output_file)
        return str(output_file)


def main():
    """Command-line interface for testing analysis engine."""
    import argparse

    parser = argparse.ArgumentParser(description='GitLab Security Audit Analysis Engine')
    parser.add_argument('detection_results', help='Path to detection results JSON file')
    parser.add_argument('--output', help='Output file for analysis results')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load detection results
    with open(args.detection_results, 'r') as f:
        detection_results = json.load(f)

    # Run analysis
    engine = AnalysisEngine()
    analysis_results = engine.correlate_findings(detection_results)

    # Save results
    output_file = engine.save_analysis(analysis_results, args.output)

    # Print summary
    if analysis_results['status'] == 'success':
        summary = analysis_results['analysis_summary']['risk_statistics']
        print(f"\nAnalysis completed successfully!")
        print(f"Total findings: {summary['total_findings']}")
        print(f"Risk summary: {summary['risk_summary']}")
        print(f"Results saved to: {output_file}")
    else:
        print(f"\nAnalysis failed: {analysis_results.get('error', 'Unknown error')}")


if __name__ == '__main__':
    main()