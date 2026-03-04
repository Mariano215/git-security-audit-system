# tests/test_analysis_engine.py
import pytest
from scripts.analysis_engine import AnalysisEngine
from scripts.risk_classifier import RiskClassifier

def test_analysis_engine_initialization():
    engine = AnalysisEngine()
    assert engine is not None
    assert hasattr(engine, 'correlate_findings')
    assert hasattr(engine, 'classify_risks')

def test_correlate_findings_removes_duplicates():
    engine = AnalysisEngine()
    findings = {
        "status": "success",
        "results": {
            "gitleaks": {
                "status": "success",
                "findings": [{"Secret": "abc123", "File": "test.py", "RuleID": "test-rule"}]
            },
            "semgrep": {
                "status": "success",
                "findings": [{"message": "abc123", "path": "test.py", "check_id": "test-rule"}]
            }
        }
    }
    result = engine.correlate_findings(findings)
    assert len(result["correlated"]) == 1

def test_risk_classifier_scores_correctly():
    classifier = RiskClassifier()
    finding = {
        "secret_type": "aws",
        "file_path": ".env",
        "tools_detected": ["gitleaks", "semgrep"]
    }
    score = classifier.calculate_risk_score(finding)
    assert score > 5.0  # Should be high risk

def test_risk_classifier_classification():
    classifier = RiskClassifier()

    # Test critical risk
    critical_finding = {
        "secret_type": "aws",
        "file_path": ".env",
        "tools_detected": ["gitleaks", "semgrep", "trufflehog"],
        "verified": True
    }
    score = classifier.calculate_risk_score(critical_finding)
    level = classifier.classify_risk_level(score)
    assert level in ["CRITICAL", "HIGH"]

    # Test low risk
    low_finding = {
        "secret_type": "generic",
        "file_path": "docs/example.md",
        "tools_detected": ["gitleaks"]
    }
    score = classifier.calculate_risk_score(low_finding)
    level = classifier.classify_risk_level(score)
    assert level in ["LOW", "INFO", "MEDIUM"]

def test_analysis_engine_handles_empty_results():
    engine = AnalysisEngine()
    empty_findings = {
        "status": "success",
        "results": {}
    }
    result = engine.correlate_findings(empty_findings)
    assert result["status"] == "success"
    assert len(result["correlated"]) == 0

def test_analysis_engine_handles_failed_detection():
    engine = AnalysisEngine()
    failed_findings = {
        "status": "error",
        "error": "Scan failed"
    }
    result = engine.correlate_findings(failed_findings)
    assert result["status"] == "error"
    assert "error" in result

def test_normalize_gitleaks_finding():
    engine = AnalysisEngine()
    gitleaks_finding = {
        "Secret": "AKIA1234567890ABCDEF",
        "File": "/path/to/.env",
        "RuleID": "aws-access-key-id",
        "StartLine": 10,
        "Description": "AWS Access Key ID",
        "Tags": ["aws", "key"]
    }

    normalized = engine._normalize_finding(gitleaks_finding, "gitleaks")

    assert normalized["source_tool"] == "gitleaks"
    assert normalized["secret_type"] == "aws"
    assert normalized["file_path"] == "/path/to/.env"
    assert normalized["line_number"] == 10
    assert "signature" in normalized

def test_normalize_semgrep_finding():
    engine = AnalysisEngine()
    semgrep_finding = {
        "message": "Hardcoded AWS key found",
        "path": "/path/to/config.py",
        "check_id": "security.aws.hardcoded-key",
        "start": {"line": 15, "col": 10}
    }

    normalized = engine._normalize_finding(semgrep_finding, "semgrep")

    assert normalized["source_tool"] == "semgrep"
    assert normalized["file_path"] == "/path/to/config.py"
    assert normalized["line_number"] == 15
    assert "signature" in normalized

def test_deduplication_merges_tools():
    engine = AnalysisEngine()

    # Create two findings that should be considered duplicates
    finding1 = {
        "id": "test1",
        "source_tool": "gitleaks",
        "tools_detected": ["gitleaks"],
        "signature": "duplicate_sig",
        "secret_value": "test_secret",
        "file_path": "test.py",
        "raw_finding": {"original": "gitleaks_data"}
    }

    finding2 = {
        "id": "test2",
        "source_tool": "semgrep",
        "tools_detected": ["semgrep"],
        "signature": "duplicate_sig",  # Same signature
        "secret_value": "test_secret",
        "file_path": "test.py",
        "raw_finding": {"original": "semgrep_data"}
    }

    deduplicated = engine._deduplicate_findings([finding1, finding2])

    assert len(deduplicated) == 1
    assert len(deduplicated[0]["tools_detected"]) == 2
    assert "gitleaks" in deduplicated[0]["tools_detected"]
    assert "semgrep" in deduplicated[0]["tools_detected"]

def test_business_context_multiplier():
    classifier = RiskClassifier()

    # Test CMMC project multiplier
    business_context = {
        "project_type": "PS-CMMC-V3",
        "environment": "production",
        "handles_customer_data": True
    }

    multiplier = classifier._get_business_context_multiplier(business_context)
    assert multiplier > 1.0  # Should increase risk

def test_analysis_summary_generation():
    engine = AnalysisEngine()

    sample_findings = {
        "status": "success",
        "scan_info": {
            "project_path": "/test/path",
            "scan_duration": "0:00:05",
            "tools_successful": ["gitleaks", "semgrep"]
        },
        "results": {
            "gitleaks": {
                "status": "success",
                "findings": [
                    {
                        "Secret": "aws_key_123",
                        "File": ".env",
                        "RuleID": "aws-access-key-id",
                        "Tags": ["aws"]
                    }
                ]
            }
        }
    }

    result = engine.correlate_findings(sample_findings)

    assert "analysis_summary" in result
    assert "risk_statistics" in result["analysis_summary"]
    assert "recommendations" in result["analysis_summary"]