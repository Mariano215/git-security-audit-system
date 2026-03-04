#!/usr/bin/env python3
"""
scanner_engine.py - Detection Engine Core for GitLab Security Audit System

This module provides the core detection engine that orchestrates all security scanners.
It runs multiple tools in parallel and provides consistent JSON output for analysis.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from .detection_config import (
        GITLEAKS_CONFIG,
        SEMGREP_CONFIG,
        TRUFFLEHOG_CONFIG,
        BASE_DIR,
        REPORTS_DIR
    )
except ImportError:
    from detection_config import (
        GITLEAKS_CONFIG,
        SEMGREP_CONFIG,
        TRUFFLEHOG_CONFIG,
        BASE_DIR,
        REPORTS_DIR
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DetectionEngine:
    """Core detection engine that orchestrates all security scanners."""

    def __init__(self) -> None:
        """Initialize the detection engine."""
        self.tools_dir: Path = BASE_DIR / "tools"
        self.reports_dir: Path = Path(REPORTS_DIR)
        self.reports_dir.mkdir(exist_ok=True)

        # Tool paths - check both local tools and system PATH
        self.tool_paths: Dict[str, str] = self._discover_tool_paths()

        logger.info("Detection engine initialized")
        logger.info("Available tools: %s", list(self.tool_paths.keys()))

    def _discover_tool_paths(self) -> Dict[str, str]:
        """Discover paths to security tools."""
        tools = {}

        # Check local tools directory first
        local_tools = {
            'gitleaks': self.tools_dir / 'gitleaks',
            'trufflehog': self.tools_dir / 'trufflehog'
        }

        for tool, path in local_tools.items():
            if path.exists() and path.is_file():
                tools[tool] = str(path)
                logger.info("Found %s at %s", tool, path)

        # Check system PATH for semgrep and any missing tools
        system_tools = ['semgrep', 'gitleaks', 'trufflehog']
        for tool in system_tools:
            if tool not in tools:
                try:
                    result = subprocess.run(['which', tool], capture_output=True, text=True)
                    if result.returncode == 0:
                        tools[tool] = result.stdout.strip()
                        logger.info("Found %s in system PATH: %s", tool, tools[tool])
                except (OSError, subprocess.SubprocessError) as e:
                    logger.debug("Could not find %s in system PATH: %s", tool, e)

        return tools

    def _get_tool_version(self, tool: str) -> str:
        """Get version of a security tool."""
        if tool not in self.tool_paths:
            return "Not installed"

        try:
            if tool == 'gitleaks':
                result = subprocess.run([self.tool_paths[tool], 'version'],
                                      capture_output=True, text=True, timeout=10)
            elif tool == 'semgrep':
                result = subprocess.run([self.tool_paths[tool], '--version'],
                                      capture_output=True, text=True, timeout=10)
            elif tool == 'trufflehog':
                result = subprocess.run([self.tool_paths[tool], '--version'],
                                      capture_output=True, text=True, timeout=10)
            else:
                return "Unknown tool"

            if result.returncode == 0:
                return result.stdout.strip() or result.stderr.strip()
            else:
                return f"Error getting version: {result.stderr.strip()}"

        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            logger.error("Error getting %s version: %s", tool, e)
            return f"Error: {str(e)}"

    def run_gitleaks(self, project_path: str) -> Dict[str, any]:
        """Run gitleaks scanner on a project."""
        # Input validation to prevent directory traversal
        project_path = os.path.abspath(project_path)
        if not os.path.exists(project_path):
            return {
                "status": "error",
                "error": f"Project path does not exist: {project_path}",
                "findings": []
            }

        logger.info("Running gitleaks scan on %s", project_path)

        if 'gitleaks' not in self.tool_paths:
            return {
                "status": "error",
                "error": "gitleaks not found",
                "findings": []
            }

        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp_file:
                tmp_path = tmp_file.name

            cmd = [
                self.tool_paths['gitleaks'],
                'detect',
                '--source', project_path,
                '--config', str(GITLEAKS_CONFIG['config_file']),
                '--report-format', 'json',
                '--report-path', tmp_path,
                '--no-git'
            ]

            if GITLEAKS_CONFIG['verbose']:
                cmd.append('--verbose')

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Gitleaks returns exit code 1 when secrets are found, 0 when none found
            if result.returncode in [0, 1]:
                try:
                    with open(tmp_path, 'r') as f:
                        findings = json.load(f)

                    return {
                        "status": "success",
                        "tool_version": self._get_tool_version('gitleaks'),
                        "scan_time": datetime.now().isoformat(),
                        "findings": findings if isinstance(findings, list) else [],
                        "findings_count": len(findings) if isinstance(findings, list) else 0
                    }
                except json.JSONDecodeError:
                    # If JSON is invalid, check if file is empty (no findings)
                    return {
                        "status": "success",
                        "tool_version": self._get_tool_version('gitleaks'),
                        "scan_time": datetime.now().isoformat(),
                        "findings": [],
                        "findings_count": 0
                    }
            else:
                return {
                    "status": "error",
                    "error": f"gitleaks failed with code {result.returncode}: {result.stderr}",
                    "findings": []
                }

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error": "gitleaks scan timed out",
                "findings": []
            }
        except (OSError, subprocess.SubprocessError) as e:
            logger.error("Error running gitleaks: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "findings": []
            }
        finally:
            # Clean up temp file
            try:
                os.unlink(tmp_path)
            except (OSError, FileNotFoundError):
                pass

    def run_semgrep(self, project_path: str) -> Dict[str, any]:
        """Run semgrep scanner on a project."""
        # Input validation to prevent directory traversal
        project_path = os.path.abspath(project_path)
        if not os.path.exists(project_path):
            return {
                "status": "error",
                "error": f"Project path does not exist: {project_path}",
                "findings": []
            }

        logger.info("Running semgrep scan on %s", project_path)

        if 'semgrep' not in self.tool_paths:
            return {
                "status": "error",
                "error": "semgrep not found",
                "findings": []
            }

        try:
            cmd = [
                self.tool_paths['semgrep'],
                '--config', 'auto',  # Use semgrep's auto-detection
                '--json',
                '--quiet',
                project_path
            ]

            # Add specific rule sets
            for rule in SEMGREP_CONFIG['rules']:
                cmd.extend(['--config', rule])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                try:
                    findings = json.loads(result.stdout)
                    results = findings.get('results', [])

                    return {
                        "status": "success",
                        "tool_version": self._get_tool_version('semgrep'),
                        "scan_time": datetime.now().isoformat(),
                        "findings": results,
                        "findings_count": len(results)
                    }
                except json.JSONDecodeError as e:
                    return {
                        "status": "error",
                        "error": f"Failed to parse semgrep JSON output: {e}",
                        "findings": []
                    }
            else:
                return {
                    "status": "error",
                    "error": f"semgrep failed with code {result.returncode}: {result.stderr}",
                    "findings": []
                }

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error": "semgrep scan timed out",
                "findings": []
            }
        except (OSError, subprocess.SubprocessError) as e:
            logger.error("Error running semgrep: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "findings": []
            }

    def run_trufflehog(self, project_path: str) -> Dict[str, any]:
        """Run trufflehog scanner on a project."""
        # Input validation to prevent directory traversal
        project_path = os.path.abspath(project_path)
        if not os.path.exists(project_path):
            return {
                "status": "error",
                "error": f"Project path does not exist: {project_path}",
                "findings": []
            }

        logger.info("Running trufflehog scan on %s", project_path)

        if 'trufflehog' not in self.tool_paths:
            return {
                "status": "error",
                "error": "trufflehog not found",
                "findings": []
            }

        try:
            cmd = [
                self.tool_paths['trufflehog'],
                'filesystem',
                project_path,
                '--json'
            ]

            if not TRUFFLEHOG_CONFIG['only_verified']:
                cmd.append('--no-verification')

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                findings = []
                if result.stdout.strip():
                    # trufflehog outputs one JSON object per line
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                findings.append(finding)
                            except json.JSONDecodeError:
                                logger.warning("Failed to parse trufflehog line: %s", line)

                return {
                    "status": "success",
                    "tool_version": self._get_tool_version('trufflehog'),
                    "scan_time": datetime.now().isoformat(),
                    "findings": findings,
                    "findings_count": len(findings)
                }
            else:
                return {
                    "status": "error",
                    "error": f"trufflehog failed with code {result.returncode}: {result.stderr}",
                    "findings": []
                }

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error": "trufflehog scan timed out",
                "findings": []
            }
        except (OSError, subprocess.SubprocessError) as e:
            logger.error("Error running trufflehog: %s", e)
            return {
                "status": "error",
                "error": str(e),
                "findings": []
            }

    def scan_project(self, project_path: str, tools: Optional[List[str]] = None,
                    parallel: bool = True) -> Dict[str, any]:
        """
        Scan a project with specified security tools.

        Args:
            project_path: Path to the project to scan
            tools: List of tools to run (default: all available)
            parallel: Whether to run tools in parallel (default: True)

        Returns:
            Dict containing results from all tools
        """
        project_path = os.path.abspath(project_path)

        if not os.path.exists(project_path):
            return {
                "status": "error",
                "error": f"Project path does not exist: {project_path}",
                "results": {}
            }

        # Determine which tools to run
        available_tools = {
            'gitleaks': self.run_gitleaks,
            'semgrep': self.run_semgrep,
            'trufflehog': self.run_trufflehog
        }

        if tools is None:
            tools_to_run = {name: func for name, func in available_tools.items()
                          if name in self.tool_paths}
        else:
            tools_to_run = {name: func for name, func in available_tools.items()
                          if name in tools and name in self.tool_paths}

        if not tools_to_run:
            return {
                "status": "error",
                "error": "No available tools to run",
                "results": {}
            }

        logger.info("Scanning %s with tools: %s", project_path, list(tools_to_run.keys()))

        scan_start = datetime.now()
        results = {}

        if parallel and len(tools_to_run) > 1:
            # Run tools in parallel
            with ThreadPoolExecutor(max_workers=len(tools_to_run)) as executor:
                future_to_tool = {
                    executor.submit(func, project_path): tool_name
                    for tool_name, func in tools_to_run.items()
                }

                for future in as_completed(future_to_tool):
                    tool_name = future_to_tool[future]
                    try:
                        results[tool_name] = future.result()
                    except Exception as e:
                        logger.error("Tool %s failed: %s", tool_name, e)
                        results[tool_name] = {
                            "status": "error",
                            "error": str(e),
                            "findings": []
                        }
        else:
            # Run tools sequentially
            for tool_name, func in tools_to_run.items():
                try:
                    results[tool_name] = func(project_path)
                except Exception as e:
                    logger.error("Tool %s failed: %s", tool_name, e)
                    results[tool_name] = {
                        "status": "error",
                        "error": str(e),
                        "findings": []
                    }

        scan_end = datetime.now()

        # Calculate summary statistics
        total_findings = sum(
            result.get('findings_count', 0) for result in results.values()
        )

        successful_tools = [
            tool for tool, result in results.items()
            if result.get('status') == 'success'
        ]

        return {
            "status": "success",
            "scan_info": {
                "project_path": project_path,
                "scan_start": scan_start.isoformat(),
                "scan_end": scan_end.isoformat(),
                "scan_duration": str(scan_end - scan_start),
                "tools_requested": list(tools_to_run.keys()),
                "tools_successful": successful_tools,
                "parallel_execution": parallel
            },
            "summary": {
                "total_findings": total_findings,
                "tools_run": len(tools_to_run),
                "tools_successful": len(successful_tools)
            },
            "results": results
        }

    def save_results(self, results: Dict[str, any], output_file: Optional[str] = None) -> str:
        """Save scan results to a JSON file."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.reports_dir / f"security_scan_{timestamp}.json"
        else:
            output_file = Path(output_file)

        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        logger.info("Results saved to %s", output_file)
        return str(output_file)


def main():
    """Command-line interface for the detection engine."""
    import argparse

    parser = argparse.ArgumentParser(description='GitLab Security Audit Detection Engine')
    parser.add_argument('project_path', help='Path to the project to scan')
    parser.add_argument('--tools', nargs='+',
                       choices=['gitleaks', 'semgrep', 'trufflehog'],
                       help='Tools to run (default: all available)')
    parser.add_argument('--no-parallel', action='store_true',
                       help='Disable parallel execution')
    parser.add_argument('--output', help='Output file for results')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    engine = DetectionEngine()
    results = engine.scan_project(
        args.project_path,
        tools=args.tools,
        parallel=not args.no_parallel
    )

    output_file = engine.save_results(results, args.output)

    # Print summary
    if results['status'] == 'success':
        summary = results['summary']
        print("\nScan completed successfully!")
        print(f"Total findings: {summary['total_findings']}")
        print(f"Tools run: {summary['tools_run']}")
        print(f"Results saved to: {output_file}")
    else:
        print(f"\nScan failed: {results.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == '__main__':
    main()