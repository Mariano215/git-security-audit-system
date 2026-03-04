# scripts/detection_config.py
"""Configuration for security detection tools"""

import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_DIR = BASE_DIR / "config"
REPORTS_DIR = BASE_DIR / "reports"

# Tool configurations
GITLEAKS_CONFIG = {
    "config_file": CONFIG_DIR / "gitleaks.toml",
    "output_format": "json",
    "verbose": True
}

SEMGREP_CONFIG = {
    "rules": [
        "p/security-audit",
        "p/secrets",
        "p/owasp-top-ten"
    ],
    "output_format": "json",
    "severity": ["ERROR", "WARNING", "INFO"]
}

TRUFFLEHOG_CONFIG = {
    "output_format": "json",
    "only_verified": False,
    "include_detectors": [
        "aws",
        "gcp",
        "azure",
        "github",
        "gitlab",
        "mysql",
        "postgres",
        "mongodb"
    ]
}

# Risk scoring weights
RISK_WEIGHTS = {
    "tool_consensus": 2.0,  # Multiple tools found same secret
    "secret_type": {
        "aws": 3.0,
        "database": 2.5,
        "api_key": 2.0,
        "ssh_key": 2.5,
        "jwt": 1.5,
        "generic": 1.0
    },
    "file_location": {
        ".env": 3.0,
        "config": 2.5,
        "src": 2.0,
        "test": 1.0,
        "docs": 0.5
    }
}