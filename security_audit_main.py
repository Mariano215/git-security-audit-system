#!/usr/bin/env python3
"""
security_audit_main.py - Main Security Audit Orchestrator

This is the main entry point for the Git Security Audit System. It coordinates
all pipeline layers (Detection, Analysis, Remediation) and provides both
programmatic API and CLI interfaces for comprehensive security auditing.

Usage:
    python security_audit_main.py [OPTIONS] PROJECT_PATHS...

Example:
    python security_audit_main.py ../dms ../ps-cmmc-v3 --config custom_config.yml --auto-remediate
"""

import argparse
import json
import logging
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Import engines from previous tasks
try:
    from scripts.scanner_engine import DetectionEngine
    from scripts.analysis_engine import AnalysisEngine
    from scripts.remediation_engine import RemediationEngine
except ImportError:
    # Fallback for direct execution
    sys.path.append(str(Path(__file__).parent / "scripts"))
    from scanner_engine import DetectionEngine
    from analysis_engine import AnalysisEngine
    from remediation_engine import RemediationEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityAuditOrchestrator:
    """
    Main orchestrator that coordinates the entire security pipeline.

    This class provides the primary interface for running security audits,
    integrating DetectionEngine, AnalysisEngine, and RemediationEngine to
    provide comprehensive security analysis with reporting.
    """

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialize the security audit orchestrator.

        Args:
            config_path: Path to custom configuration file (optional)
        """
        self.config_path = config_path or self._get_default_config_path()
        self.config = self.load_config()
        self.reports_dir = Path(self.config.get("audit_settings", {})
                               .get("reporting", {})
                               .get("output_directory", "reports"))
        self.reports_dir.mkdir(exist_ok=True)

        # Initialize engines
        try:
            self.detection_engine = DetectionEngine()
            self.analysis_engine = AnalysisEngine()
            self.remediation_engine = RemediationEngine()
            logger.info("All engines initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize engines: {e}")
            raise

    def _get_default_config_path(self) -> str:
        """Get the default configuration file path."""
        config_path = Path(__file__).parent / "config" / "audit_config.yml"
        return str(config_path)

    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from YAML file.

        Returns:
            Configuration dictionary

        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid
        """
        config_path = Path(self.config_path)

        if not config_path.exists():
            logger.error(f"Configuration file not found: {config_path}")
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except yaml.YAMLError as e:
            logger.error(f"Invalid YAML configuration: {e}")
            raise

    def run_full_audit(self, project_paths: List[str],
                      auto_remediate: bool = False,
                      output_formats: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run a comprehensive security audit on specified projects.

        Args:
            project_paths: List of project directories to audit
            auto_remediate: Whether to perform automated remediation
            output_formats: Report output formats (json, markdown, html)

        Returns:
            Comprehensive audit report dictionary

        Raises:
            Exception: If audit fails
        """
        logger.info(f"Starting full security audit on {len(project_paths)} projects")
        audit_start_time = datetime.now()

        # Validate project paths
        validated_paths = self._validate_project_paths(project_paths)
        if not validated_paths:
            raise ValueError("No valid project paths provided")

        audit_results = {
            "timestamp": audit_start_time.isoformat(),
            "projects_scanned": validated_paths,
            "config_used": self.config_path,
            "audit_summary": {},
            "detection_results": {},
            "analysis_results": {},
            "remediation_results": {},
            "total_issues": 0,
            "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "execution_time_seconds": 0
        }

        try:
            # Phase 1: Detection - Run security scanners
            logger.info("Phase 1: Running security detection...")
            detection_results = {}
            total_detections = 0

            for project_path in validated_paths:
                logger.info(f"Scanning project: {project_path}")
                project_results = self.detection_engine.scan_project(project_path)
                detection_results[project_path] = project_results

                # Count total detections
                if isinstance(project_results, dict) and "summary" in project_results:
                    total_detections += project_results["summary"].get("total_findings", 0)

            audit_results["detection_results"] = detection_results
            logger.info(f"Detection completed. Found {total_detections} total findings")

            # Phase 2: Analysis - Correlate and analyze findings
            logger.info("Phase 2: Running analysis and correlation...")
            analysis_results = {}
            total_issues = 0

            for project_path, project_detections in detection_results.items():
                logger.info(f"Analyzing findings for: {project_path}")
                project_analysis = self.analysis_engine.correlate_findings(project_detections)
                analysis_results[project_path] = project_analysis

                # Update risk distribution
                if isinstance(project_analysis, dict) and "risk_summary" in project_analysis:
                    risk_summary = project_analysis["risk_summary"]
                    for risk_level in ["critical", "high", "medium", "low"]:
                        audit_results["risk_distribution"][risk_level] += risk_summary.get(risk_level, 0)

                # Count total issues
                if isinstance(project_analysis, dict) and "total_findings" in project_analysis:
                    total_issues += project_analysis["total_findings"]

            audit_results["analysis_results"] = analysis_results
            audit_results["total_issues"] = total_issues
            logger.info(f"Analysis completed. {total_issues} issues identified")

            # Phase 3: Remediation (optional)
            remediation_results = {}
            if auto_remediate:
                logger.info("Phase 3: Running automated remediation...")

                for project_path, project_analysis in analysis_results.items():
                    if isinstance(project_analysis, dict) and "findings" in project_analysis:
                        logger.info(f"Remediating issues in: {project_path}")
                        project_remediation = self.remediation_engine.remediate_multiple_findings(
                            project_analysis["findings"]
                        )
                        remediation_results[project_path] = project_remediation

                audit_results["remediation_results"] = remediation_results
                logger.info("Automated remediation completed")
            else:
                logger.info("Phase 3: Skipped (auto-remediation disabled)")

            # Calculate execution time
            audit_end_time = datetime.now()
            execution_time = (audit_end_time - audit_start_time).total_seconds()
            audit_results["execution_time_seconds"] = execution_time

            # Generate audit summary
            audit_results["audit_summary"] = self._generate_audit_summary(audit_results)

            logger.info(f"Security audit completed in {execution_time:.2f} seconds")
            return audit_results

        except Exception as e:
            logger.error(f"Audit failed: {e}")
            raise

    def _validate_project_paths(self, project_paths: List[str]) -> List[str]:
        """
        Validate that project paths exist and are readable.

        Args:
            project_paths: List of project paths to validate

        Returns:
            List of valid project paths
        """
        validated_paths = []

        for path_str in project_paths:
            path = Path(path_str).resolve()

            if not path.exists():
                logger.warning(f"Path does not exist: {path}")
                continue

            if not path.is_dir():
                logger.warning(f"Path is not a directory: {path}")
                continue

            validated_paths.append(str(path))

        logger.info(f"Validated {len(validated_paths)} of {len(project_paths)} project paths")
        return validated_paths

    def _generate_audit_summary(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate executive summary of audit results.

        Args:
            audit_results: Complete audit results

        Returns:
            Executive summary dictionary
        """
        risk_dist = audit_results.get("risk_distribution", {})
        total_projects = len(audit_results.get("projects_scanned", []))

        # Calculate security score (0-100, higher is better)
        total_issues = audit_results.get("total_issues", 0)
        critical_issues = risk_dist.get("critical", 0)
        high_issues = risk_dist.get("high", 0)

        # Simple scoring algorithm
        if total_issues == 0:
            security_score = 100
        else:
            penalty = (critical_issues * 20) + (high_issues * 10) + (total_issues * 2)
            security_score = max(0, 100 - penalty)

        return {
            "total_projects_scanned": total_projects,
            "total_issues_found": total_issues,
            "security_score": security_score,
            "risk_breakdown": risk_dist,
            "execution_time_seconds": audit_results.get("execution_time_seconds", 0),
            "timestamp": audit_results.get("timestamp"),
            "recommendations": self._generate_recommendations(audit_results)
        }

    def _generate_recommendations(self, audit_results: Dict[str, Any]) -> List[str]:
        """
        Generate actionable recommendations based on audit results.

        Args:
            audit_results: Complete audit results

        Returns:
            List of actionable recommendations
        """
        recommendations = []
        risk_dist = audit_results.get("risk_distribution", {})

        if risk_dist.get("critical", 0) > 0:
            recommendations.append("URGENT: Address critical security issues immediately")
            recommendations.append("Consider implementing emergency security patches")

        if risk_dist.get("high", 0) > 0:
            recommendations.append("Schedule high-priority security fixes within 24-48 hours")
            recommendations.append("Review access controls and authentication mechanisms")

        if risk_dist.get("medium", 0) > 0:
            recommendations.append("Plan medium-priority fixes for next development cycle")
            recommendations.append("Implement additional security monitoring")

        if audit_results.get("total_issues", 0) == 0:
            recommendations.append("Excellent! No security issues detected")
            recommendations.append("Maintain current security practices and continue regular audits")

        # Always include general recommendations
        recommendations.extend([
            "Implement regular automated security scanning in CI/CD pipeline",
            "Provide security training for development team",
            "Establish incident response procedures for security issues"
        ])

        return recommendations[:5]  # Limit to top 5 recommendations

    def generate_report(self, audit_results: Dict[str, Any],
                       format_type: str = "json",
                       output_path: Optional[str] = None) -> str:
        """
        Generate audit report in specified format.

        Args:
            audit_results: Complete audit results
            format_type: Output format (json, markdown, html)
            output_path: Optional file path to save report

        Returns:
            Formatted report string

        Raises:
            ValueError: If format_type is not supported
        """
        if format_type.lower() == "json":
            report = self._generate_json_report(audit_results)
        elif format_type.lower() == "markdown":
            report = self._generate_markdown_report(audit_results)
        elif format_type.lower() == "html":
            report = self._generate_html_report(audit_results)
        else:
            raise ValueError(f"Unsupported report format: {format_type}")

        # Save to file if path specified
        if output_path:
            with open(output_path, 'w') as f:
                f.write(report)
            logger.info(f"Report saved to: {output_path}")

        return report

    def _generate_json_report(self, audit_results: Dict[str, Any]) -> str:
        """Generate JSON formatted report."""
        return json.dumps(audit_results, indent=2, default=str)

    def _generate_markdown_report(self, audit_results: Dict[str, Any]) -> str:
        """Generate Markdown formatted report."""
        summary = audit_results.get("audit_summary", {})
        risk_dist = summary.get("risk_breakdown", {})

        report = f"""# Security Audit Report

**Generated:** {summary.get('timestamp', 'Unknown')}
**Projects Scanned:** {summary.get('total_projects_scanned', 0)}
**Total Issues:** {summary.get('total_issues_found', 0)}
**Security Score:** {summary.get('security_score', 0)}/100

## Executive Summary

This security audit scanned {summary.get('total_projects_scanned', 0)} projects and identified {summary.get('total_issues_found', 0)} security issues.

### Risk Distribution
- **Critical:** {risk_dist.get('critical', 0)} issues
- **High:** {risk_dist.get('high', 0)} issues
- **Medium:** {risk_dist.get('medium', 0)} issues
- **Low:** {risk_dist.get('low', 0)} issues

### Key Recommendations
"""

        recommendations = summary.get("recommendations", [])
        for i, rec in enumerate(recommendations, 1):
            report += f"{i}. {rec}\n"

        report += f"""
## Scan Details

**Execution Time:** {summary.get('execution_time_seconds', 0):.2f} seconds

### Projects Audited
"""

        for project in audit_results.get("projects_scanned", []):
            report += f"- {project}\n"

        report += """
---
*Report generated by Git Security Audit System*
"""

        return report

    def _generate_html_report(self, audit_results: Dict[str, Any]) -> str:
        """Generate HTML formatted report."""
        summary = audit_results.get("audit_summary", {})
        risk_dist = summary.get("risk_breakdown", {})

        # Simple HTML template
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        .summary {{ background-color: #f5f5f5; padding: 20px; margin: 20px 0; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .score {{ font-size: 24px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Audit Report</h1>
        <p>Generated: {summary.get('timestamp', 'Unknown')}</p>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Projects Scanned:</strong> {summary.get('total_projects_scanned', 0)}</p>
        <p><strong>Total Issues:</strong> {summary.get('total_issues_found', 0)}</p>
        <p><strong>Security Score:</strong> <span class="score">{summary.get('security_score', 0)}/100</span></p>

        <h3>Risk Distribution</h3>
        <ul>
            <li class="critical">Critical: {risk_dist.get('critical', 0)} issues</li>
            <li class="high">High: {risk_dist.get('high', 0)} issues</li>
            <li class="medium">Medium: {risk_dist.get('medium', 0)} issues</li>
            <li class="low">Low: {risk_dist.get('low', 0)} issues</li>
        </ul>
    </div>

    <h2>Recommendations</h2>
    <ol>
"""

        for rec in summary.get("recommendations", []):
            html += f"        <li>{rec}</li>\n"

        html += """    </ol>

    <h2>Projects Audited</h2>
    <ul>
"""

        for project in audit_results.get("projects_scanned", []):
            html += f"        <li>{project}</li>\n"

        html += f"""    </ul>

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc; color: #666;">
        <p>Report generated by Git Security Audit System</p>
        <p>Execution Time: {summary.get('execution_time_seconds', 0):.2f} seconds</p>
    </footer>
</body>
</html>"""

        return html


def setup_cli_parser() -> argparse.ArgumentParser:
    """
    Set up command-line argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="Git Security Audit System - Comprehensive security analysis",
        epilog="Example: python security_audit_main.py ../dms ../ps-cmmc-v3 --auto-remediate",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Positional arguments
    parser.add_argument(
        'projects',
        nargs='*',
        help='Project directories to audit (default: configured projects)'
    )

    # Configuration options
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to custom configuration file'
    )

    # Scan options
    parser.add_argument(
        '--auto-remediate',
        action='store_true',
        help='Enable automatic remediation of security issues'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['json', 'markdown', 'html'],
        default=['json', 'markdown'],
        nargs='+',
        help='Output report formats (default: json markdown)'
    )

    parser.add_argument(
        '--output-dir', '-o',
        type=str,
        help='Output directory for reports (default: reports/)'
    )

    # Logging options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress all but error messages'
    )

    return parser


def main() -> int:
    """
    Main CLI entry point.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    parser = setup_cli_parser()
    args = parser.parse_args()

    # Configure logging based on arguments
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Initialize orchestrator
        orchestrator = SecurityAuditOrchestrator(config_path=args.config)

        # Determine project paths
        project_paths = args.projects
        if not project_paths:
            # Use default paths from config
            default_paths = orchestrator.config.get("audit_settings", {}).get("projects", {}).get("default_paths", [])
            project_paths = default_paths

        if not project_paths:
            logger.error("No project paths specified and no default paths configured")
            return 1

        # Run audit
        logger.info("Starting security audit...")
        results = orchestrator.run_full_audit(
            project_paths=project_paths,
            auto_remediate=args.auto_remediate,
            output_formats=args.format
        )

        # Generate reports
        output_dir = Path(args.output_dir) if args.output_dir else orchestrator.reports_dir
        output_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        for format_type in args.format:
            output_path = output_dir / f"security_audit_report_{timestamp}.{format_type}"
            report = orchestrator.generate_report(results, format_type, str(output_path))
            logger.info(f"Report generated: {output_path}")

        # Print summary
        summary = results.get("audit_summary", {})
        print(f"\n{'='*60}")
        print("SECURITY AUDIT COMPLETED")
        print(f"{'='*60}")
        print(f"Projects Scanned: {summary.get('total_projects_scanned', 0)}")
        print(f"Issues Found: {summary.get('total_issues_found', 0)}")
        print(f"Security Score: {summary.get('security_score', 0)}/100")
        print(f"Execution Time: {summary.get('execution_time_seconds', 0):.2f}s")

        risk_dist = summary.get('risk_breakdown', {})
        if any(risk_dist.values()):
            print(f"\nRisk Distribution:")
            if risk_dist.get('critical', 0) > 0:
                print(f"  Critical: {risk_dist['critical']}")
            if risk_dist.get('high', 0) > 0:
                print(f"  High: {risk_dist['high']}")
            if risk_dist.get('medium', 0) > 0:
                print(f"  Medium: {risk_dist['medium']}")
            if risk_dist.get('low', 0) > 0:
                print(f"  Low: {risk_dist['low']}")

        print(f"{'='*60}")

        # Return appropriate exit code
        critical_issues = summary.get('risk_breakdown', {}).get('critical', 0)
        high_issues = summary.get('risk_breakdown', {}).get('high', 0)

        if critical_issues > 0 or high_issues > 5:  # More than 5 high issues
            return 1  # Error exit code for CI/CD integration

        return 0  # Success

    except KeyboardInterrupt:
        logger.info("Audit interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())