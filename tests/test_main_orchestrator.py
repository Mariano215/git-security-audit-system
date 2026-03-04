#!/usr/bin/env python3
"""
test_main_orchestrator.py - TDD Tests for Main Security Audit Orchestrator

This module provides comprehensive tests for the main orchestrator that coordinates
the entire security pipeline and provides both programmatic and CLI interfaces.
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import will fail initially - this is expected for TDD
try:
    from security_audit_main import SecurityAuditOrchestrator
except ImportError:
    SecurityAuditOrchestrator = None


class TestSecurityAuditOrchestrator:
    """Test cases for the SecurityAuditOrchestrator class."""

    def test_orchestrator_initialization(self):
        """Test that orchestrator can be initialized properly."""
        if SecurityAuditOrchestrator is None:
            pytest.skip("SecurityAuditOrchestrator not yet implemented")

        orchestrator = SecurityAuditOrchestrator()
        assert orchestrator is not None
        assert hasattr(orchestrator, 'run_full_audit')
        assert hasattr(orchestrator, 'load_config')
        assert hasattr(orchestrator, 'generate_report')

    def test_run_audit_returns_report(self):
        """Test that running an audit returns a properly structured report."""
        if SecurityAuditOrchestrator is None:
            pytest.skip("SecurityAuditOrchestrator not yet implemented")

        with tempfile.TemporaryDirectory() as temp_dir:
            orchestrator = SecurityAuditOrchestrator()
            report = orchestrator.run_full_audit([temp_dir])

            # Verify report structure
            assert isinstance(report, dict)
            assert "audit_summary" in report
            assert "projects_scanned" in report
            assert "timestamp" in report
            assert "total_issues" in report
            assert "risk_distribution" in report

    def test_config_loading(self):
        """Test that configuration can be loaded from YAML."""
        if SecurityAuditOrchestrator is None:
            pytest.skip("SecurityAuditOrchestrator not yet implemented")

        orchestrator = SecurityAuditOrchestrator()

        # Should load default config initially
        assert orchestrator.config is not None
        assert "audit_settings" in orchestrator.config

    def test_report_generation_formats(self):
        """Test that reports can be generated in multiple formats."""
        if SecurityAuditOrchestrator is None:
            pytest.skip("SecurityAuditOrchestrator not yet implemented")

        with tempfile.TemporaryDirectory() as temp_dir:
            orchestrator = SecurityAuditOrchestrator()

            # Mock audit results
            mock_results = {
                "audit_summary": {"total_projects": 1},
                "projects_scanned": [temp_dir],
                "timestamp": "2024-01-01T00:00:00",
                "total_issues": 0,
                "risk_distribution": {"high": 0, "medium": 0, "low": 0}
            }

            # Test JSON format
            json_report = orchestrator.generate_report(mock_results, format_type="json")
            assert isinstance(json_report, str)
            json.loads(json_report)  # Should be valid JSON

            # Test Markdown format
            md_report = orchestrator.generate_report(mock_results, format_type="markdown")
            assert isinstance(md_report, str)
            assert "# Security Audit Report" in md_report

    def test_cli_integration(self):
        """Test CLI argument parsing and integration."""
        if SecurityAuditOrchestrator is None:
            pytest.skip("SecurityAuditOrchestrator not yet implemented")

        with tempfile.TemporaryDirectory() as temp_dir:
            # Test that CLI can be invoked programmatically
            with patch('sys.argv', ['security_audit_main.py', temp_dir]):
                try:
                    from security_audit_main import main
                    # Should not raise exceptions
                    result = main()
                    assert result in [0, 1]  # Valid exit codes
                except SystemExit as e:
                    assert e.code in [0, 1]

    def test_engine_integration(self):
        """Test integration with DetectionEngine, AnalysisEngine, and RemediationEngine."""
        if SecurityAuditOrchestrator is None:
            pytest.skip("SecurityAuditOrchestrator not yet implemented")

        orchestrator = SecurityAuditOrchestrator()

        # Should have access to engines
        assert hasattr(orchestrator, 'detection_engine')
        assert hasattr(orchestrator, 'analysis_engine')
        assert hasattr(orchestrator, 'remediation_engine')

    def test_error_handling(self):
        """Test proper error handling for invalid inputs."""
        if SecurityAuditOrchestrator is None:
            pytest.skip("SecurityAuditOrchestrator not yet implemented")

        orchestrator = SecurityAuditOrchestrator()

        # Test with non-existent path
        with pytest.raises(Exception):  # Should handle gracefully
            orchestrator.run_full_audit(["/non/existent/path"])