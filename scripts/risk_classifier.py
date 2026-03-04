#!/usr/bin/env python3
"""
risk_classifier.py - Risk Classification System for GitLab Security Audit System

This module provides comprehensive risk scoring and classification for security findings.
It evaluates findings based on multiple factors including tool consensus, secret type,
and file location to produce accurate risk assessments.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from .detection_config import RISK_WEIGHTS
except ImportError:
    from detection_config import RISK_WEIGHTS

# Configure logging
logger = logging.getLogger(__name__)


class RiskClassifier:
    """
    Risk classification system that scores and categorizes security findings.

    The classifier evaluates findings based on multiple risk factors:
    - Tool consensus: How many tools detected the same issue
    - Secret type: What kind of secret was found (AWS, database, etc.)
    - File location: Where the secret was found (.env, config, source, etc.)
    """

    def __init__(self) -> None:
        """Initialize the risk classifier with configuration weights."""
        self.risk_weights = RISK_WEIGHTS
        self.risk_levels = {
            "CRITICAL": (8.0, float('inf')),
            "HIGH": (6.0, 8.0),
            "MEDIUM": (4.0, 6.0),
            "LOW": (2.0, 4.0),
            "INFO": (0.0, 2.0)
        }

        logger.info("Risk classifier initialized with weights: %s", self.risk_weights)

    def calculate_risk_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate comprehensive risk score for a finding.

        Args:
            finding: Dictionary containing finding details with keys:
                - secret_type: Type of secret detected
                - file_path: Path to file containing the secret
                - tools_detected: List of tools that detected this finding
                - verified: Optional boolean if secret is verified

        Returns:
            Float risk score (higher = more risky)
        """
        score = 0.0

        # Tool consensus score - multiple tools increase confidence
        tools_detected = finding.get('tools_detected', [])
        if len(tools_detected) > 1:
            consensus_multiplier = len(tools_detected) - 1
            tool_consensus_score = self.risk_weights['tool_consensus'] * consensus_multiplier
            score += tool_consensus_score
            logger.debug("Tool consensus score: %.2f (tools: %s)",
                        tool_consensus_score, tools_detected)

        # Secret type score
        secret_type = finding.get('secret_type', 'generic')
        secret_type_score = self._get_secret_type_score(secret_type)
        score += secret_type_score
        logger.debug("Secret type score: %.2f (type: %s)", secret_type_score, secret_type)

        # File location score
        file_path = finding.get('file_path', '')
        file_location_score = self._get_file_location_score(file_path)
        score += file_location_score
        logger.debug("File location score: %.2f (path: %s)", file_location_score, file_path)

        # Verification bonus - verified secrets are definitely real
        if finding.get('verified', False):
            verification_bonus = 2.0
            score += verification_bonus
            logger.debug("Verification bonus: %.2f", verification_bonus)

        # Business context multiplier for sensitive projects
        business_context = finding.get('business_context', {})
        if business_context:
            context_multiplier = self._get_business_context_multiplier(business_context)
            score *= context_multiplier
            logger.debug("Business context multiplier: %.2f", context_multiplier)

        logger.debug("Final risk score: %.2f for finding in %s", score, file_path)
        return round(score, 2)

    def _get_secret_type_score(self, secret_type: str) -> float:
        """Get risk score for secret type."""
        secret_type = secret_type.lower()

        # Direct match first
        if secret_type in self.risk_weights['secret_type']:
            return self.risk_weights['secret_type'][secret_type]

        # Pattern matching for complex secret types
        type_patterns = {
            'aws': ['amazon', 'aws', 's3', 'ec2', 'iam'],
            'database': ['mysql', 'postgres', 'mongodb', 'redis', 'db', 'database'],
            'api_key': ['api', 'key', 'token', 'bearer'],
            'ssh_key': ['ssh', 'private', 'rsa', 'ed25519'],
            'jwt': ['jwt', 'json web token']
        }

        for risk_type, patterns in type_patterns.items():
            if any(pattern in secret_type for pattern in patterns):
                return self.risk_weights['secret_type'].get(risk_type, 1.0)

        return self.risk_weights['secret_type']['generic']

    def _get_file_location_score(self, file_path: str) -> float:
        """Get risk score based on file location."""
        if not file_path:
            return 0.0

        file_path = file_path.lower()
        path_obj = Path(file_path)

        # Check exact filename matches first
        filename = path_obj.name
        if filename in self.risk_weights['file_location']:
            return self.risk_weights['file_location'][filename]

        # Check directory patterns
        path_parts = path_obj.parts

        # High risk files/directories
        high_risk_patterns = ['.env', 'config', 'secret', 'credential', 'key']
        for pattern in high_risk_patterns:
            if any(pattern in part for part in path_parts):
                return self.risk_weights['file_location'].get(pattern, 2.5)

        # Medium risk - source code
        if any(part in ['src', 'source', 'lib', 'app'] for part in path_parts):
            return self.risk_weights['file_location']['src']

        # Low risk - test files
        if any(part in ['test', 'tests', 'spec'] for part in path_parts):
            return self.risk_weights['file_location']['test']

        # Very low risk - documentation
        if any(part in ['doc', 'docs', 'documentation', 'readme'] for part in path_parts):
            return self.risk_weights['file_location']['docs']

        # Default to medium risk for unknown locations
        return 1.5

    def _get_business_context_multiplier(self, business_context: Dict[str, Any]) -> float:
        """Calculate business context risk multiplier."""
        multiplier = 1.0

        # High-value project types
        project_type = business_context.get('project_type', '').lower()
        if 'cmmc' in project_type or 'compliance' in project_type:
            multiplier *= 1.5  # Compliance projects need extra security
        elif 'dms' in project_type or 'defense' in project_type:
            multiplier *= 1.3  # Defense projects are sensitive

        # Production environment
        if business_context.get('environment') == 'production':
            multiplier *= 1.2

        # Customer data handling
        if business_context.get('handles_customer_data', False):
            multiplier *= 1.3

        return multiplier

    def classify_risk_level(self, risk_score: float) -> str:
        """
        Classify risk score into risk level.

        Args:
            risk_score: Numerical risk score

        Returns:
            Risk level string (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        for level, (min_score, max_score) in self.risk_levels.items():
            if min_score <= risk_score < max_score:
                return level

        # Fallback to INFO for very low scores
        return "INFO"

    def classify_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Classify a list of findings by risk level.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary with risk levels as keys and lists of findings as values
        """
        classified = {level: [] for level in self.risk_levels.keys()}

        for finding in findings:
            risk_score = self.calculate_risk_score(finding)
            risk_level = self.classify_risk_level(risk_score)

            # Add risk information to the finding
            enhanced_finding = finding.copy()
            enhanced_finding.update({
                'risk_score': risk_score,
                'risk_level': risk_level
            })

            classified[risk_level].append(enhanced_finding)

        return classified

    def get_risk_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate risk statistics for a set of findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary containing risk statistics
        """
        if not findings:
            return {
                'total_findings': 0,
                'risk_distribution': {level: 0 for level in self.risk_levels.keys()},
                'average_risk_score': 0.0,
                'highest_risk_score': 0.0,
                'risk_summary': 'No findings to analyze'
            }

        classified = self.classify_findings(findings)
        scores = [self.calculate_risk_score(finding) for finding in findings]

        # Calculate distribution
        risk_distribution = {level: len(findings) for level, findings in classified.items()}

        # Calculate statistics
        total_findings = len(findings)
        average_score = sum(scores) / total_findings if scores else 0.0
        highest_score = max(scores) if scores else 0.0

        # Generate summary
        critical_count = risk_distribution['CRITICAL']
        high_count = risk_distribution['HIGH']

        if critical_count > 0:
            summary = f"CRITICAL: {critical_count} critical security issues require immediate attention"
        elif high_count > 0:
            summary = f"HIGH RISK: {high_count} high-risk issues found"
        elif risk_distribution['MEDIUM'] > 0:
            summary = f"MEDIUM RISK: {risk_distribution['MEDIUM']} medium-risk issues found"
        else:
            summary = "LOW RISK: Only low-risk or informational findings"

        return {
            'total_findings': total_findings,
            'risk_distribution': risk_distribution,
            'average_risk_score': round(average_score, 2),
            'highest_risk_score': round(highest_score, 2),
            'risk_summary': summary
        }


def main():
    """Command-line interface for testing risk classification."""
    import json

    # Example usage
    classifier = RiskClassifier()

    # Test finding
    test_finding = {
        'secret_type': 'aws',
        'file_path': '.env',
        'tools_detected': ['gitleaks', 'trufflehog'],
        'verified': True,
        'business_context': {
            'project_type': 'PS-CMMC-V3',
            'environment': 'production',
            'handles_customer_data': True
        }
    }

    score = classifier.calculate_risk_score(test_finding)
    level = classifier.classify_risk_level(score)

    print(f"Test Finding Risk Assessment:")
    print(f"Score: {score}")
    print(f"Level: {level}")
    print(f"Details: {json.dumps(test_finding, indent=2)}")


if __name__ == '__main__':
    main()