#!/usr/bin/env python3
"""
secret_rotator.py - Secret Rotation Script Generator for GitLab Security Audit System

This module generates rotation scripts for different types of secrets found during
security audits. It provides automated rotation procedures with rollback capabilities.
"""

import logging
import secrets
import string
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)


class SecretRotator:
    """
    Generates rotation scripts for different types of secrets.

    This class creates platform-specific rotation scripts that can:
    - Generate new secure secrets
    - Update cloud provider credentials
    - Rotate database passwords
    - Update API keys and tokens
    - Provide rollback procedures
    """

    def __init__(self):
        """Initialize the secret rotator."""
        logger.info("Secret rotator initialized")

    def generate_rotation_script(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a rotation script based on the secret type in the finding.

        Args:
            finding: Normalized finding from analysis engine

        Returns:
            Dictionary containing rotation script and metadata
        """
        secret_type = finding.get('secret_type', 'generic').lower()

        logger.info("Generating rotation script for secret type: %s", secret_type)

        rotation_methods = {
            'aws': self._generate_aws_rotation,
            'database': self._generate_database_rotation,
            'api_key': self._generate_api_key_rotation,
            'jwt': self._generate_jwt_rotation,
            'ssh_key': self._generate_ssh_key_rotation,
            'generic': self._generate_generic_rotation
        }

        # Get the appropriate rotation method
        rotation_method = rotation_methods.get(secret_type, self._generate_generic_rotation)

        try:
            return rotation_method(finding)
        except Exception as e:
            logger.error("Failed to generate rotation script for %s: %s", secret_type, str(e))
            return {
                'status': 'error',
                'error': f"Failed to generate rotation script: {str(e)}",
                'secret_type': secret_type
            }

    def _generate_aws_rotation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AWS credential rotation script."""
        script_content = """#!/bin/bash
# AWS Credential Rotation Script
# Generated on {timestamp}
# WARNING: Review and test in non-production environment first

set -e

echo "=== AWS Credential Rotation ==="
echo "This script will rotate AWS access keys for security"
echo "Current access key will be deactivated after new one is created"

# Check if AWS CLI is available
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI not found. Please install AWS CLI first."
    exit 1
fi

# Get current user info
echo "Getting current AWS user information..."
CURRENT_USER=$(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)
echo "Current user: $CURRENT_USER"

# List current access keys
echo "Current access keys:"
aws iam list-access-keys --user-name "$CURRENT_USER"

# Create new access key
echo "Creating new access key..."
NEW_KEY_OUTPUT=$(aws iam create-access-key --user-name "$CURRENT_USER")
NEW_ACCESS_KEY=$(echo "$NEW_KEY_OUTPUT" | jq -r '.AccessKey.AccessKeyId')
NEW_SECRET_KEY=$(echo "$NEW_KEY_OUTPUT" | jq -r '.AccessKey.SecretAccessKey')

echo "New access key created: $NEW_ACCESS_KEY"
echo "IMPORTANT: Update your applications with these new credentials:"
echo "AWS_ACCESS_KEY_ID=$NEW_ACCESS_KEY"
echo "AWS_SECRET_ACCESS_KEY=$NEW_SECRET_KEY"

read -p "Have you updated all applications with the new credentials? (y/N): " confirm
if [[ $confirm != [yY] ]]; then
    echo "Rotation cancelled. Clean up the new key if not needed:"
    echo "aws iam delete-access-key --user-name $CURRENT_USER --access-key-id $NEW_ACCESS_KEY"
    exit 1
fi

# Deactivate old key (replace with actual old key ID)
OLD_ACCESS_KEY="{old_key_placeholder}"
if [ ! -z "$OLD_ACCESS_KEY" ] && [ "$OLD_ACCESS_KEY" != "{old_key_placeholder}" ]; then
    echo "Deactivating old access key: $OLD_ACCESS_KEY"
    aws iam update-access-key --access-key-id "$OLD_ACCESS_KEY" --status Inactive --user-name "$CURRENT_USER"

    echo "Waiting 10 seconds before deletion..."
    sleep 10

    echo "Deleting old access key: $OLD_ACCESS_KEY"
    aws iam delete-access-key --access-key-id "$OLD_ACCESS_KEY" --user-name "$CURRENT_USER"
fi

echo "=== AWS Credential Rotation Complete ==="
echo "New credentials have been activated and old ones removed"
""".format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            old_key_placeholder="{old_key_placeholder}"
        )

        rollback_script = """#!/bin/bash
# AWS Credential Rollback Script
# Use this if the new credentials cause issues

set -e

echo "=== AWS Credential Rollback ==="
echo "This will reactivate the previous access key"

OLD_ACCESS_KEY="{old_key_placeholder}"
CURRENT_USER=$(aws sts get-caller-identity --query 'Arn' --output text | cut -d'/' -f2)

if [ ! -z "$OLD_ACCESS_KEY" ] && [ "$OLD_ACCESS_KEY" != "{old_key_placeholder}" ]; then
    echo "Reactivating old access key: $OLD_ACCESS_KEY"
    aws iam update-access-key --access-key-id "$OLD_ACCESS_KEY" --status Active --user-name "$CURRENT_USER"
    echo "Old access key reactivated"
else
    echo "No old key specified for rollback"
fi
""".format(old_key_placeholder="{old_key_placeholder}")

        return {
            'status': 'success',
            'secret_type': 'aws',
            'rotation_script': script_content,
            'rollback_script': rollback_script,
            'instructions': [
                "1. Review the rotation script carefully",
                "2. Test in non-production environment first",
                "3. Update all applications with new credentials before proceeding",
                "4. Run the rotation script",
                "5. Monitor applications for any issues",
                "6. Use rollback script if problems occur"
            ],
            'estimated_downtime': '5-10 minutes',
            'prerequisites': ['AWS CLI installed', 'IAM permissions for key management']
        }

    def _generate_database_rotation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate database password rotation script."""
        new_password_var = "NEW_DB_PASSWORD"

        script_content = """#!/bin/bash
# Database Password Rotation Script
# Generated on {timestamp}
# WARNING: Test in non-production environment first

set -e

echo "=== Database Password Rotation ==="

# Configuration - Set these environment variables before running
DB_HOST="${{DB_HOST:-localhost}}"
DB_PORT="${{DB_PORT:-5432}}"
DB_NAME="${{DB_NAME:-your_database}}"
DB_USER="${{DB_USER:-your_user}}"
OLD_PASSWORD="${{OLD_DB_PASSWORD}}"
NEW_PASSWORD="${{{new_password_var}}}"

# Validate required environment variables
if [ -z "$OLD_PASSWORD" ]; then
    echo "ERROR: OLD_DB_PASSWORD environment variable is required"
    exit 1
fi

if [ -z "$NEW_PASSWORD" ]; then
    echo "ERROR: {new_password_var} environment variable is required"
    exit 1
fi

# Check if database is accessible
echo "Testing database connection..."
if command -v psql &> /dev/null; then
    # PostgreSQL
    PGPASSWORD="$OLD_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null
    echo "PostgreSQL connection successful"

    echo "Updating password..."
    PGPASSWORD="$OLD_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "ALTER USER $DB_USER PASSWORD '$NEW_PASSWORD';"

    echo "Testing new password..."
    PGPASSWORD="$NEW_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null

elif command -v mysql &> /dev/null; then
    # MySQL
    mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$OLD_PASSWORD" -e "SELECT 1;" "$DB_NAME" > /dev/null
    echo "MySQL connection successful"

    echo "Updating password..."
    mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$OLD_PASSWORD" -e "ALTER USER '$DB_USER'@'%' IDENTIFIED BY '$NEW_PASSWORD';" "$DB_NAME"
    mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$OLD_PASSWORD" -e "FLUSH PRIVILEGES;" "$DB_NAME"

    echo "Testing new password..."
    mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$NEW_PASSWORD" -e "SELECT 1;" "$DB_NAME" > /dev/null

else
    echo "ERROR: Neither psql nor mysql found. Install database client."
    exit 1
fi

echo "=== Database Password Rotation Complete ==="
echo "New password has been set from environment variable"
echo "Update your application configuration with the new password"
""".format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            new_password_var=new_password_var
        )

        rollback_script = """#!/bin/bash
# Database Password Rollback Script

set -e

echo "=== Database Password Rollback ==="

DB_HOST="${{DB_HOST:-localhost}}"
DB_PORT="${{DB_PORT:-5432}}"
DB_NAME="${{DB_NAME:-your_database}}"
DB_USER="${{DB_USER:-your_user}}"
CURRENT_PASSWORD="${{CURRENT_DB_PASSWORD}}"
OLD_PASSWORD="${{OLD_DB_PASSWORD}}"

echo "Rolling back to previous password..."

if command -v psql &> /dev/null; then
    PGPASSWORD="$CURRENT_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "ALTER USER $DB_USER PASSWORD '$OLD_PASSWORD';"
elif command -v mysql &> /dev/null; then
    mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$CURRENT_PASSWORD" -e "ALTER USER '$DB_USER'@'%' IDENTIFIED BY '$OLD_PASSWORD';" "$DB_NAME"
    mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$CURRENT_PASSWORD" -e "FLUSH PRIVILEGES;" "$DB_NAME"
fi

echo "Password rollback complete"
"""

        return {
            'status': 'success',
            'secret_type': 'database',
            'rotation_script': script_content,
            'rollback_script': rollback_script,
            'new_password_var': new_password_var,
            'instructions': [
                f"1. Set environment variables: OLD_DB_PASSWORD and {new_password_var}",
                "2. Set database connection variables (DB_HOST, DB_PORT, DB_NAME, DB_USER)",
                "3. Test the script in non-production first",
                "4. Run the rotation script",
                "5. Update application configuration",
                "6. Restart applications to use new password"
            ],
            'estimated_downtime': '2-5 minutes',
            'prerequisites': ['Database client (psql/mysql)', 'Database admin access']
        }

    def _generate_api_key_rotation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate API key rotation script."""
        api_key_var = "NEW_API_KEY"

        script_content = """#!/bin/bash
# API Key Rotation Script
# Generated on {timestamp}

echo "=== API Key Rotation ==="
echo "This is a template script for API key rotation"
echo "Customize this script based on your specific API provider"

# Validate required environment variables
if [ -z "${{{api_key_var}}}" ]; then
    echo "ERROR: {api_key_var} environment variable is required"
    echo "Generate a new API key from your provider's dashboard and set:"
    echo "export {api_key_var}=your_new_api_key_here"
    exit 1
fi

echo "Steps to rotate API key:"
echo "1. Log in to your API provider's dashboard"
echo "2. Generate a new API key and set {api_key_var} environment variable"
echo "3. Update your applications with the new key"
echo "4. Test that the new key works"
echo "5. Revoke the old API key"

echo "New API key will be read from environment variable"
echo "Update your environment variables:"
echo "API_KEY=${{{api_key_var}}}"

# Common API providers rotation examples:
echo ""
echo "=== Provider-specific examples ==="
echo ""
echo "GitHub API:"
echo "curl -H 'Authorization: token NEW_TOKEN' https://api.github.com/user"
echo ""
echo "Stripe API:"
echo "curl https://api.stripe.com/v1/charges -u NEW_API_KEY:"
echo ""
echo "AWS API Gateway:"
echo "aws apigateway get-api-keys --query 'items[0].id'"
""".format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            api_key_var=api_key_var
        )

        return {
            'status': 'success',
            'secret_type': 'api_key',
            'rotation_script': script_content,
            'api_key_var': api_key_var,
            'instructions': [
                f"1. Generate new API key from provider dashboard",
                f"2. Set environment variable: export {api_key_var}=your_new_key",
                "3. Run the rotation script to validate",
                "4. Update application configuration",
                "5. Test API functionality with new key",
                "6. Revoke old API key",
                "7. Monitor for any issues"
            ],
            'estimated_downtime': '0-2 minutes',
            'prerequisites': ['API provider dashboard access', 'Application restart capability']
        }

    def _generate_jwt_rotation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JWT secret rotation script."""
        new_secret = self._generate_secure_password(32)

        script_content = """#!/bin/bash
# JWT Secret Rotation Script
# Generated on {timestamp}

echo "=== JWT Secret Rotation ==="
echo "WARNING: This will invalidate ALL existing JWT tokens"

NEW_JWT_SECRET="{new_secret}"

echo "New JWT secret: $NEW_JWT_SECRET"
echo ""
echo "Steps for JWT secret rotation:"
echo "1. Update JWT_SECRET in your application configuration"
echo "2. Restart all application instances"
echo "3. All users will need to re-authenticate"
echo "4. Monitor authentication logs for issues"

echo ""
echo "Environment variable update:"
echo "JWT_SECRET=$NEW_JWT_SECRET"

echo ""
echo "IMPORTANT: All existing tokens will be invalid after rotation!"
""".format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            new_secret=new_secret
        )

        return {
            'status': 'success',
            'secret_type': 'jwt',
            'rotation_script': script_content,
            'new_secret': new_secret,
            'instructions': [
                "1. Schedule maintenance window for token rotation",
                "2. Update JWT_SECRET in all application instances",
                "3. Restart applications simultaneously",
                "4. Notify users they need to re-authenticate",
                "5. Monitor authentication systems"
            ],
            'estimated_downtime': '5-15 minutes',
            'prerequisites': ['Coordinated application restart', 'User notification system']
        }

    def _generate_ssh_key_rotation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate SSH key rotation script."""
        script_content = """#!/bin/bash
# SSH Key Rotation Script
# Generated on {timestamp}

echo "=== SSH Key Rotation ==="

# Generate new SSH key pair
echo "Generating new SSH key pair..."
ssh-keygen -t ed25519 -C "rotated-$(date +%Y%m%d)" -f ~/.ssh/id_ed25519_new -N ""

echo "New SSH key pair generated:"
echo "Private key: ~/.ssh/id_ed25519_new"
echo "Public key: ~/.ssh/id_ed25519_new.pub"

echo ""
echo "Public key content:"
cat ~/.ssh/id_ed25519_new.pub

echo ""
echo "Steps to complete SSH key rotation:"
echo "1. Copy the public key above"
echo "2. Add it to authorized_keys on all target servers"
echo "3. Update deployment scripts and CI/CD systems"
echo "4. Test SSH connections with new key"
echo "5. Remove old key from authorized_keys"
echo "6. Delete old private key file"

echo ""
echo "Test new key:"
echo "ssh -i ~/.ssh/id_ed25519_new user@server"
""".format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        return {
            'status': 'success',
            'secret_type': 'ssh_key',
            'rotation_script': script_content,
            'instructions': [
                "1. Run the script to generate new SSH key pair",
                "2. Add new public key to all target servers",
                "3. Update deployment and automation scripts",
                "4. Test connections with new key",
                "5. Remove old key from servers",
                "6. Securely delete old private key"
            ],
            'estimated_downtime': '10-30 minutes',
            'prerequisites': ['SSH access to target servers', 'Deployment script update access']
        }

    def _generate_generic_rotation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate generic secret rotation script."""
        new_secret = self._generate_secure_password(24)

        script_content = """#!/bin/bash
# Generic Secret Rotation Script
# Generated on {timestamp}

echo "=== Generic Secret Rotation ==="
echo "Found secret type: {secret_type}"
echo "File: {file_path}"

NEW_SECRET="{new_secret}"

echo "Generated new secret: $NEW_SECRET"
echo ""
echo "Manual rotation steps:"
echo "1. Identify where this secret is used"
echo "2. Generate or obtain new secret value"
echo "3. Update all systems using the secret"
echo "4. Test functionality with new secret"
echo "5. Revoke or disable old secret"
echo "6. Monitor for any issues"

echo ""
echo "Update environment variable:"
echo "SECRET_NAME=$NEW_SECRET"
""".format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            secret_type=finding.get('secret_type', 'unknown'),
            file_path=finding.get('file_path', 'unknown'),
            new_secret=new_secret
        )

        return {
            'status': 'success',
            'secret_type': 'generic',
            'rotation_script': script_content,
            'new_secret': new_secret,
            'instructions': [
                "1. Identify all systems using this secret",
                "2. Generate appropriate replacement secret",
                "3. Update all dependent systems",
                "4. Test functionality thoroughly",
                "5. Disable old secret"
            ],
            'estimated_downtime': 'Variable',
            'prerequisites': ['System inventory', 'Update access to all dependent systems']
        }

    def _generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure password."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def _generate_api_key(self) -> str:
        """Generate a secure API key."""
        return 'sk-' + ''.join(secrets.choice(string.ascii_letters + string.digits)
                              for _ in range(32))

    def validate_rotation_prerequisites(self, secret_type: str) -> Dict[str, Any]:
        """
        Validate that prerequisites for rotation are met.

        Args:
            secret_type: Type of secret to validate

        Returns:
            Validation results
        """
        validations = {
            'aws': self._validate_aws_prerequisites,
            'database': self._validate_database_prerequisites,
            'ssh_key': self._validate_ssh_prerequisites
        }

        validator = validations.get(secret_type, self._validate_generic_prerequisites)
        return validator()

    def _validate_aws_prerequisites(self) -> Dict[str, Any]:
        """Validate AWS rotation prerequisites."""
        import shutil

        checks = {
            'aws_cli_installed': shutil.which('aws') is not None,
            'jq_installed': shutil.which('jq') is not None
        }

        return {
            'status': 'success' if all(checks.values()) else 'warning',
            'checks': checks,
            'missing_tools': [tool for tool, available in checks.items() if not available]
        }

    def _validate_database_prerequisites(self) -> Dict[str, Any]:
        """Validate database rotation prerequisites."""
        import shutil

        checks = {
            'psql_available': shutil.which('psql') is not None,
            'mysql_available': shutil.which('mysql') is not None
        }

        # At least one database client should be available
        has_db_client = any(checks.values())

        return {
            'status': 'success' if has_db_client else 'warning',
            'checks': checks,
            'has_database_client': has_db_client
        }

    def _validate_ssh_prerequisites(self) -> Dict[str, Any]:
        """Validate SSH key rotation prerequisites."""
        import shutil

        checks = {
            'ssh_keygen_available': shutil.which('ssh-keygen') is not None,
            'ssh_available': shutil.which('ssh') is not None
        }

        return {
            'status': 'success' if all(checks.values()) else 'warning',
            'checks': checks,
            'missing_tools': [tool for tool, available in checks.items() if not available]
        }

    def _validate_generic_prerequisites(self) -> Dict[str, Any]:
        """Validate generic rotation prerequisites."""
        return {
            'status': 'success',
            'checks': {},
            'message': 'Manual validation required for generic secret type'
        }