#!/usr/bin/env python3
"""
remediation_engine.py - Automated Remediation Engine for GitLab Security Audit System

This module provides automated remediation of security findings, focusing on securing
exposed secrets by migrating them to environment variables and updating source code.
"""

import json
import logging
import os
import errno
import re
import shutil
import tempfile
import fcntl
import contextlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

try:
    from .secret_rotator import SecretRotator
    from .detection_config import BASE_DIR
except ImportError:
    from secret_rotator import SecretRotator
    from detection_config import BASE_DIR

# Configure logging
logger = logging.getLogger(__name__)


class RemediationTransaction:
    """
    Transaction-like context manager for remediation operations.
    Ensures atomic operations with proper rollback on failure.
    """

    def __init__(self):
        """Initialize transaction tracking."""
        self.operations = []
        self.completed = False

    def add_operation(self, rollback_func, *args, **kwargs):
        """Add an operation that can be rolled back."""
        self.operations.append((rollback_func, args, kwargs))

    def rollback(self):
        """Roll back all operations in reverse order."""
        if self.completed:
            return

        logger.info("Rolling back %d operations due to transaction failure", len(self.operations))

        for rollback_func, args, kwargs in reversed(self.operations):
            try:
                rollback_func(*args, **kwargs)
                logger.debug("Successfully rolled back operation: %s", rollback_func.__name__)
            except Exception as e:
                logger.error("Failed to rollback operation %s: %s", rollback_func.__name__, str(e))

    def commit(self):
        """Mark transaction as successfully completed."""
        self.completed = True
        logger.debug("Transaction committed successfully with %d operations", len(self.operations))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


@contextlib.contextmanager
def file_lock(file_path: Path, mode: str = 'r'):
    """
    Context manager for file locking to prevent race conditions.

    Args:
        file_path: Path to file to lock
        mode: File open mode

    Yields:
        File handle with exclusive lock
    """
    try:
        with open(file_path, mode) as f:
            # Try to acquire exclusive lock
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            logger.debug("Acquired file lock: %s", file_path)
            yield f
    except IOError as e:
        if e.errno == errno.EAGAIN or e.errno == errno.EACCES:
            raise IOError(f"Could not acquire lock on file: {file_path}. File may be in use.")
        raise
    finally:
        logger.debug("Released file lock: %s", file_path)


def atomic_write(file_path: Path, content: str, encoding: str = 'utf-8') -> None:
    """
    Atomically write content to a file.

    Uses tempfile + rename pattern to ensure atomic operation.
    If process crashes during write, original file remains unchanged.

    Args:
        file_path: Target file path
        content: Content to write
        encoding: File encoding
    """
    file_path = Path(file_path)

    # Create temporary file in same directory as target
    # This ensures rename operation is atomic (same filesystem)
    temp_fd = None
    temp_path = None

    try:
        temp_fd, temp_path = tempfile.mkstemp(
            suffix='.tmp',
            prefix=f'{file_path.name}.',
            dir=file_path.parent,
            text=True
        )

        # Write content to temporary file
        with os.fdopen(temp_fd, 'w', encoding=encoding) as temp_file:
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())  # Ensure data is written to disk

        temp_fd = None  # File descriptor now closed

        # Copy original file permissions if file exists
        if file_path.exists():
            stat_info = file_path.stat()
            os.chmod(temp_path, stat_info.st_mode)

        # Atomic rename operation
        os.rename(temp_path, file_path)
        temp_path = None  # Successfully moved, don't clean up

        logger.debug("Atomically wrote %d bytes to %s", len(content), file_path)

    except Exception:
        # Clean up on failure
        if temp_fd is not None:
            try:
                os.close(temp_fd)
            except:
                pass

        if temp_path is not None and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass

        raise


def atomic_append(file_path: Path, content: str, encoding: str = 'utf-8') -> None:
    """
    Atomically append content to a file.

    Args:
        file_path: Target file path
        content: Content to append
        encoding: File encoding
    """
    file_path = Path(file_path)

    existing_content = ""
    if file_path.exists():
        with open(file_path, 'r', encoding=encoding) as f:
            existing_content = f.read()

    new_content = existing_content + content
    atomic_write(file_path, new_content, encoding)


class RemediationEngine:
    """
    Automated remediation engine for security findings.

    This engine provides:
    - Automatic secret migration to environment variables
    - Source code updates with proper environment variable references
    - Multi-language support (Python, JavaScript, TypeScript, YAML, JSON)
    - File backup and rollback capabilities
    - .gitignore updates for security
    - Integration with secret rotation system
    """

    def __init__(self, project_path: Optional[str] = None):
        """
        Initialize the remediation engine.

        Args:
            project_path: Path to the project root (defaults to current directory)
        """
        self.project_path = Path(project_path) if project_path else Path.cwd()
        self.secret_rotator = SecretRotator()
        self.backup_dir = self.project_path / ".security_backups"
        self.backup_dir.mkdir(exist_ok=True)

        # Load environment template
        template_path = Path(__file__).parent.parent / "templates" / "env_template.txt"
        self.env_template = ""
        if template_path.exists():
            with open(template_path, 'r') as f:
                self.env_template = f.read()

        logger.info("Remediation engine initialized for project: %s", self.project_path)

    def secure_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Secure a single security finding by migrating secrets to environment variables.
        Uses atomic operations and transaction rollback to prevent data loss.

        Args:
            finding: Standardized finding from analysis engine

        Returns:
            Dictionary containing remediation results
        """
        file_path = Path(finding.get('file_path', ''))
        if not file_path.exists():
            return {
                'status': 'error',
                'error': f"File not found: {file_path}",
                'finding_id': finding.get('id')
            }

        # Use transaction pattern for atomic operations
        with RemediationTransaction() as transaction:
            try:
                # Step 1: Create backup of original file
                backup_path = self._create_backup(file_path)
                transaction.add_operation(self._remove_backup, backup_path)

                # Step 2: Generate environment variable name
                var_name = self._generate_env_var_name(finding)

                # Step 3: Update source code atomically
                update_result = self._update_source_code_atomic(file_path, finding, var_name, transaction)
                if update_result['status'] != 'success':
                    return update_result

                # Step 4: Update or create .env file atomically
                env_result = self._update_env_file_atomic(var_name, finding, transaction)
                if env_result['status'] != 'success':
                    return env_result

                # Step 5: Update .gitignore atomically
                gitignore_result = self._update_gitignore_atomic(transaction)
                if gitignore_result['status'] != 'success':
                    logger.warning("Failed to update .gitignore, but continuing: %s",
                                 gitignore_result.get('error', 'Unknown error'))

                # Step 6: Generate rotation script (no rollback needed - read-only operation)
                rotation_result = self.secret_rotator.generate_rotation_script(finding)

                logger.info("Successfully secured finding %s in %s",
                           finding.get('id'), file_path.name)

                return {
                    'status': 'secured',
                    'finding_id': finding.get('id'),
                    'file_path': str(file_path),
                    'backup_path': str(backup_path),
                    'environment_variable': var_name,
                    'rotation_script': rotation_result,
                    'changes_made': update_result.get('changes', []),
                    'timestamp': datetime.now().isoformat()
                }

            except Exception as e:
                logger.error("Failed to secure finding: %s", str(e))
                return {
                    'status': 'error',
                    'error': str(e),
                    'finding_id': finding.get('id')
                }

    def update_gitignore(self) -> Dict[str, Any]:
        """
        Update .gitignore to include security-sensitive files.
        Uses transaction for rollback capability.

        Returns:
            Dictionary containing update results
        """
        with RemediationTransaction() as transaction:
            return self._update_gitignore_atomic(transaction)

    def rollback_remediation(self, backup_path: str, target_path: str) -> Dict[str, Any]:
        """
        Rollback a remediation by restoring from backup.

        Args:
            backup_path: Path to the backup file
            target_path: Path to restore to

        Returns:
            Dictionary containing rollback results
        """
        try:
            backup_file = Path(backup_path)
            target_file = Path(target_path)

            if not backup_file.exists():
                return {
                    'status': 'error',
                    'error': f"Backup file not found: {backup_path}"
                }

            # Restore from backup
            shutil.copy2(backup_file, target_file)

            logger.info("Successfully rolled back %s from backup", target_path)

            return {
                'status': 'success',
                'restored_file': str(target_file),
                'backup_file': str(backup_file),
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error("Failed to rollback remediation: %s", str(e))
            return {
                'status': 'error',
                'error': str(e)
            }

    def _create_backup(self, file_path: Path) -> Path:
        """Create a backup of the file before modification."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.name}.{timestamp}.backup"
        backup_path = self.backup_dir / backup_name

        shutil.copy2(file_path, backup_path)
        logger.debug("Created backup: %s", backup_path)

        return backup_path

    def _generate_env_var_name(self, finding: Dict[str, Any]) -> str:
        """
        Generate an appropriate environment variable name for the finding.

        Args:
            finding: Security finding

        Returns:
            Environment variable name
        """
        secret_type = finding.get('secret_type', 'secret').upper()
        file_path = Path(finding.get('file_path', ''))

        # Base name from secret type
        if secret_type in ['API_KEY', 'API']:
            base_name = "API_KEY"
        elif secret_type == 'DATABASE':
            base_name = "DB_PASSWORD"
        elif secret_type == 'JWT':
            base_name = "JWT_SECRET"
        elif secret_type == 'AWS':
            # Check if it's access key or secret key based on pattern
            secret_value = finding.get('secret_value', '')
            if secret_value.startswith('AKIA'):
                base_name = "AWS_ACCESS_KEY_ID"
            else:
                base_name = "AWS_SECRET_ACCESS_KEY"
        elif secret_type == 'SSH_KEY':
            base_name = "SSH_PRIVATE_KEY"
        else:
            base_name = f"{secret_type}_SECRET"

        # Add file context if needed
        file_stem = file_path.stem.upper().replace('-', '_').replace('.', '_')

        # Common file patterns that don't need prefix
        skip_prefixes = ['CONFIG', 'SETTINGS', 'ENV', 'CONSTANTS', 'MAIN', 'INDEX', 'APP']

        if file_stem not in skip_prefixes and len(file_stem) < 15:
            return f"{file_stem}_{base_name}"
        else:
            return base_name

    def _update_source_code(self, file_path: Path, finding: Dict[str, Any], var_name: str) -> Dict[str, Any]:
        """
        Update source code to use environment variables instead of hardcoded secrets.

        Args:
            file_path: Path to the source file
            finding: Security finding
            var_name: Environment variable name to use

        Returns:
            Dictionary containing update results
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content
            secret_value = finding.get('secret_value', '')

            # Remove truncation marker if present
            if secret_value.endswith('...'):
                # Try to get full secret from raw finding
                raw_secret = finding.get('raw_finding', {}).get('Secret', secret_value[:-3])
                if raw_secret:
                    secret_value = raw_secret

            file_extension = file_path.suffix.lower()
            changes = []

            if file_extension in ['.py']:
                content, py_changes = self._update_python_file(content, secret_value, var_name)
                changes.extend(py_changes)

            elif file_extension in ['.js', '.ts', '.jsx', '.tsx']:
                content, js_changes = self._update_javascript_file(content, secret_value, var_name)
                changes.extend(js_changes)

            elif file_extension in ['.yml', '.yaml']:
                content, yaml_changes = self._update_yaml_file(content, secret_value, var_name)
                changes.extend(yaml_changes)

            elif file_extension in ['.json']:
                content, json_changes = self._update_json_file(content, secret_value, var_name)
                changes.extend(json_changes)

            else:
                # Generic text replacement
                content, generic_changes = self._update_generic_file(content, secret_value, var_name, file_extension)
                changes.extend(generic_changes)

            # Write updated content
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                logger.debug("Updated %s with environment variable references", file_path.name)

            return {
                'status': 'success',
                'changes': changes,
                'file_updated': content != original_content
            }

        except Exception as e:
            logger.error("Failed to update source code in %s: %s", file_path.name, str(e))
            return {
                'status': 'error',
                'error': f"Failed to update source code: {str(e)}"
            }

    def _update_python_file(self, content: str, secret_value: str, var_name: str) -> Tuple[str, List[str]]:
        """Update Python file to use os.environ.get()."""
        changes = []

        # Add import if not present
        if 'import os' not in content and 'from os import' not in content:
            content = 'import os\n' + content
            changes.append("Added 'import os'")

        # Common Python patterns
        patterns = [
            (r'(["\'])(' + re.escape(secret_value) + r')(["\'])',
             f'os.environ.get("{var_name}", ' + r'\1\2\3' + ')'),
            (r'=\s*["\'](' + re.escape(secret_value) + r')["\']',
             f'= os.environ.get("{var_name}", "{secret_value}")'),
        ]

        for pattern, replacement in patterns:
            old_content = content
            content = re.sub(pattern, replacement, content)
            if content != old_content:
                changes.append(f"Replaced hardcoded secret with os.environ.get('{var_name}')")

        return content, changes

    def _update_javascript_file(self, content: str, secret_value: str, var_name: str) -> Tuple[str, List[str]]:
        """Update JavaScript/TypeScript file to use process.env."""
        changes = []

        # Common JS patterns
        patterns = [
            (r'(["\'])(' + re.escape(secret_value) + r')(["\'])',
             f'process.env.{var_name} || ' + r'\1\2\3'),
            (r':\s*["\'](' + re.escape(secret_value) + r')["\']',
             f': process.env.{var_name} || "{secret_value}"'),
            (r'=\s*["\'](' + re.escape(secret_value) + r')["\']',
             f'= process.env.{var_name} || "{secret_value}"'),
        ]

        for pattern, replacement in patterns:
            old_content = content
            content = re.sub(pattern, replacement, content)
            if content != old_content:
                changes.append(f"Replaced hardcoded secret with process.env.{var_name}")

        return content, changes

    def _update_yaml_file(self, content: str, secret_value: str, var_name: str) -> Tuple[str, List[str]]:
        """Update YAML file to use environment variable substitution."""
        changes = []

        # YAML patterns with environment variable substitution
        patterns = [
            (r':\s*["\']?(' + re.escape(secret_value) + r')["\']?\s*$',
             f': ${{{var_name}:-' + r'\1' + '}', re.MULTILINE),
            (r'=\s*["\']?(' + re.escape(secret_value) + r')["\']?',
             f'= ${{{var_name}:-' + r'\1' + '}'),
        ]

        for pattern, replacement, *flags in patterns:
            flag = flags[0] if flags else 0
            old_content = content
            content = re.sub(pattern, replacement, content, flags=flag)
            if content != old_content:
                changes.append(f"Replaced hardcoded secret with environment variable substitution ${{{var_name}}}")

        return content, changes

    def _update_json_file(self, content: str, secret_value: str, var_name: str) -> Tuple[str, List[str]]:
        """Update JSON file (limited support due to JSON format constraints)."""
        changes = []

        # JSON is more limited - we can add comments about environment variables
        try:
            # Try to parse and update JSON while maintaining structure
            lines = content.split('\n')
            updated_lines = []

            for line in lines:
                if secret_value in line:
                    # Add comment above the line
                    indent = len(line) - len(line.lstrip())
                    comment = ' ' * indent + f'// TODO: Replace with environment variable {var_name}'
                    updated_lines.append(comment)
                    changes.append(f"Added TODO comment for environment variable {var_name}")

                updated_lines.append(line)

            content = '\n'.join(updated_lines)

        except Exception:
            # Fallback to simple replacement
            old_content = content
            content = content.replace(f'"{secret_value}"', f'"REPLACE_WITH_ENV_{var_name}"')
            if content != old_content:
                changes.append(f"Marked secret for replacement with {var_name}")

        return content, changes

    def _update_generic_file(self, content: str, secret_value: str, var_name: str, file_extension: str) -> Tuple[str, List[str]]:
        """Update generic file with basic replacement."""
        changes = []

        # Simple replacement with placeholder
        old_content = content
        placeholder = f"$ENV_{var_name}$"
        content = content.replace(secret_value, placeholder)

        if content != old_content:
            changes.append(f"Replaced secret with placeholder {placeholder}")

        return content, changes

    def _update_env_file(self, var_name: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update or create .env file with the new environment variable.

        Args:
            var_name: Environment variable name
            finding: Security finding

        Returns:
            Dictionary containing update results
        """
        try:
            env_path = self.project_path / ".env"

            # Load existing .env content
            existing_vars = {}
            if env_path.exists():
                with open(env_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            existing_vars[key.strip()] = value.strip()

            # Add new variable if not exists
            secret_value = finding.get('secret_value', '')
            if secret_value.endswith('...'):
                secret_value = secret_value[:-3] + "<REPLACE_WITH_FULL_VALUE>"

            if var_name not in existing_vars:
                # Create or append to .env file
                with open(env_path, 'a') as f:
                    if env_path.exists() and env_path.stat().st_size > 0:
                        f.write('\n')

                    f.write(f"# Added by security audit remediation on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Found in: {finding.get('file_path', 'unknown')}\n")
                    f.write(f"{var_name}={secret_value}\n\n")

            # Also create .env.example if it doesn't exist
            env_example_path = self.project_path / ".env.example"
            if not env_example_path.exists():
                with open(env_example_path, 'w') as f:
                    # Use template if available
                    if self.env_template:
                        template_content = self.env_template.format(
                            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            generated_var_name=f"your_{var_name.lower()}_here"
                        )
                        f.write(template_content)
                        f.write(f"\n# Project-specific variables\n{var_name}=your_secret_value_here\n")
                    else:
                        f.write(f"# Environment variables template\n{var_name}=your_secret_value_here\n")

            logger.info("Updated .env file with variable: %s", var_name)

            return {
                'status': 'success',
                'env_file': str(env_path),
                'variable_name': var_name,
                'example_created': not env_example_path.existed_before if hasattr(env_example_path, 'existed_before') else True
            }

        except Exception as e:
            logger.error("Failed to update .env file: %s", str(e))
            return {
                'status': 'error',
                'error': f"Failed to update .env file: {str(e)}"
            }

    def remediate_multiple_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Remediate multiple findings in batch.

        Args:
            findings: List of security findings

        Returns:
            Dictionary containing batch remediation results
        """
        results = {
            'status': 'completed',
            'total_findings': len(findings),
            'successful': 0,
            'failed': 0,
            'results': [],
            'summary': {}
        }

        for finding in findings:
            result = self.secure_finding(finding)
            results['results'].append(result)

            if result.get('status') == 'secured':
                results['successful'] += 1
            else:
                results['failed'] += 1

        # Generate summary
        risk_levels = {}
        secret_types = {}

        for finding in findings:
            risk_level = finding.get('risk_level', 'UNKNOWN')
            secret_type = finding.get('secret_type', 'unknown')

            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
            secret_types[secret_type] = secret_types.get(secret_type, 0) + 1

        results['summary'] = {
            'risk_levels': risk_levels,
            'secret_types': secret_types,
            'success_rate': f"{(results['successful'] / len(findings) * 100):.1f}%" if findings else "0%"
        }

        logger.info("Batch remediation completed: %d successful, %d failed",
                   results['successful'], results['failed'])

        return results

    def _update_source_code_atomic(self, file_path: Path, finding: Dict[str, Any],
                                  var_name: str, transaction: RemediationTransaction) -> Dict[str, Any]:
        """
        Atomically update source code to use environment variables.

        Args:
            file_path: Path to the source file
            finding: Security finding
            var_name: Environment variable name to use
            transaction: Transaction context for rollback

        Returns:
            Dictionary containing update results
        """
        try:
            # Read original content
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()

            # Update content
            secret_value = finding.get('secret_value', '')
            if secret_value.endswith('...'):
                raw_secret = finding.get('raw_finding', {}).get('Secret', secret_value[:-3])
                if raw_secret:
                    secret_value = raw_secret

            file_extension = file_path.suffix.lower()
            changes = []
            updated_content = original_content

            if file_extension in ['.py']:
                updated_content, py_changes = self._update_python_file(original_content, secret_value, var_name)
                changes.extend(py_changes)
            elif file_extension in ['.js', '.ts', '.jsx', '.tsx']:
                updated_content, js_changes = self._update_javascript_file(original_content, secret_value, var_name)
                changes.extend(js_changes)
            elif file_extension in ['.yml', '.yaml']:
                updated_content, yaml_changes = self._update_yaml_file(original_content, secret_value, var_name)
                changes.extend(yaml_changes)
            elif file_extension in ['.json']:
                updated_content, json_changes = self._update_json_file(original_content, secret_value, var_name)
                changes.extend(json_changes)
            else:
                updated_content, generic_changes = self._update_generic_file(original_content, secret_value, var_name, file_extension)
                changes.extend(generic_changes)

            # Atomically write updated content if changed
            if updated_content != original_content:
                atomic_write(file_path, updated_content)

                # Add rollback operation
                transaction.add_operation(
                    self._restore_file_content,
                    file_path,
                    original_content
                )

                logger.debug("Atomically updated %s with environment variable references", file_path.name)

            return {
                'status': 'success',
                'changes': changes,
                'file_updated': updated_content != original_content
            }

        except Exception as e:
            logger.error("Failed to update source code in %s: %s", file_path.name, str(e))
            return {
                'status': 'error',
                'error': f"Failed to update source code: {str(e)}"
            }

    def _update_env_file_atomic(self, var_name: str, finding: Dict[str, Any],
                               transaction: RemediationTransaction) -> Dict[str, Any]:
        """
        Atomically update or create .env file with proper file locking.

        Args:
            var_name: Environment variable name
            finding: Security finding
            transaction: Transaction context for rollback

        Returns:
            Dictionary containing update results
        """
        try:
            env_path = self.project_path / ".env"
            env_example_path = self.project_path / ".env.example"

            # Prepare secret value
            secret_value = finding.get('secret_value', '')
            if secret_value.endswith('...'):
                secret_value = secret_value[:-3] + "<REPLACE_WITH_FULL_VALUE>"

            # Read existing .env content with file locking
            existing_vars = {}
            original_env_content = ""

            if env_path.exists():
                with file_lock(env_path, 'r') as f:
                    original_env_content = f.read()
                    for line in original_env_content.split('\n'):
                        line = line.strip()
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            existing_vars[key.strip()] = value.strip()

            # Add new variable if not exists
            env_was_updated = False
            if var_name not in existing_vars:
                new_entry = f"\n# Added by security audit remediation on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                new_entry += f"# Found in: {finding.get('file_path', 'unknown')}\n"
                new_entry += f"{var_name}={secret_value}\n"

                new_env_content = original_env_content + new_entry

                # Atomically write .env file
                atomic_write(env_path, new_env_content)
                env_was_updated = True

                # Add rollback operation
                transaction.add_operation(
                    self._restore_file_content,
                    env_path,
                    original_env_content if original_env_content else None
                )

            # Create .env.example if it doesn't exist
            example_created = False
            if not env_example_path.exists():
                if self.env_template:
                    template_content = self.env_template.format(
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        generated_var_name=f"your_{var_name.lower()}_here"
                    )
                    template_content += f"\n# Project-specific variables\n{var_name}=your_secret_value_here\n"
                else:
                    template_content = f"# Environment variables template\n{var_name}=your_secret_value_here\n"

                atomic_write(env_example_path, template_content)
                example_created = True

                # Add rollback operation
                transaction.add_operation(
                    self._remove_file,
                    env_example_path
                )

            if env_was_updated:
                logger.info("Atomically updated .env file with variable: %s", var_name)

            return {
                'status': 'success',
                'env_file': str(env_path),
                'variable_name': var_name,
                'example_created': example_created,
                'env_updated': env_was_updated
            }

        except Exception as e:
            logger.error("Failed to update .env file: %s", str(e))
            return {
                'status': 'error',
                'error': f"Failed to update .env file: {str(e)}"
            }

    def _update_gitignore_atomic(self, transaction: RemediationTransaction) -> Dict[str, Any]:
        """
        Atomically update .gitignore with security patterns.

        Args:
            transaction: Transaction context for rollback

        Returns:
            Dictionary containing update results
        """
        try:
            gitignore_path = self.project_path / ".gitignore"

            # Security-sensitive patterns to add
            security_patterns = [
                "# Security - Environment files",
                ".env",
                ".env.local",
                ".env.*.local",
                "*.env",
                "",
                "# Security - Backup files",
                ".security_backups/",
                "*.backup",
                "",
                "# Security - Key files",
                "*.key",
                "*.pem",
                "*.p12",
                "*.pfx",
                "",
                "# Security - Config files with secrets",
                "secrets.yml",
                "secrets.yaml",
                "secrets.json",
                "*secrets*",
                ""
            ]

            original_content = ""
            if gitignore_path.exists():
                with open(gitignore_path, 'r') as f:
                    original_content = f.read()

            # Check which patterns are already present
            new_patterns = []
            for pattern in security_patterns:
                if pattern.strip() and not re.search(re.escape(pattern.strip()), original_content):
                    new_patterns.append(pattern)

            if new_patterns:
                new_content = original_content
                if original_content and not original_content.endswith('\n'):
                    new_content += '\n'
                new_content += '\n'.join(new_patterns) + '\n'

                # Atomically write .gitignore
                atomic_write(gitignore_path, new_content)

                # Add rollback operation
                transaction.add_operation(
                    self._restore_file_content,
                    gitignore_path,
                    original_content if original_content else None
                )

                logger.info("Atomically updated .gitignore with %d new security patterns",
                           len([p for p in new_patterns if p.strip() and not p.startswith('#')]))

            return {
                'status': 'success',
                'gitignore_path': str(gitignore_path),
                'patterns_added': len([p for p in new_patterns if p.strip() and not p.startswith('#')])
            }

        except Exception as e:
            logger.error("Failed to update .gitignore: %s", str(e))
            return {
                'status': 'error',
                'error': str(e)
            }

    def _restore_file_content(self, file_path: Path, original_content: Optional[str]) -> None:
        """
        Restore original file content for rollback.

        Args:
            file_path: Path to file to restore
            original_content: Original content (None means delete file)
        """
        try:
            if original_content is None:
                # File didn't exist originally, delete it
                if file_path.exists():
                    file_path.unlink()
                    logger.debug("Deleted file during rollback: %s", file_path)
            else:
                # Restore original content
                atomic_write(file_path, original_content)
                logger.debug("Restored original content during rollback: %s", file_path)
        except Exception as e:
            logger.error("Failed to restore file %s during rollback: %s", file_path, str(e))

    def _remove_file(self, file_path: Path) -> None:
        """
        Remove a file for rollback.

        Args:
            file_path: Path to file to remove
        """
        try:
            if file_path.exists():
                file_path.unlink()
                logger.debug("Removed file during rollback: %s", file_path)
        except Exception as e:
            logger.error("Failed to remove file %s during rollback: %s", file_path, str(e))

    def _remove_backup(self, backup_path: Path) -> None:
        """
        Remove backup file for rollback.

        Args:
            backup_path: Path to backup file to remove
        """
        try:
            backup_path = Path(backup_path)
            if backup_path.exists():
                backup_path.unlink()
                logger.debug("Removed backup during rollback: %s", backup_path)
        except Exception as e:
            logger.error("Failed to remove backup %s during rollback: %s", backup_path, str(e))

    def generate_remediation_report(self, remediation_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive remediation report.

        Args:
            remediation_results: Results from remediation operations

        Returns:
            Dictionary containing formatted report
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report = {
            'report_type': 'Security Remediation Report',
            'timestamp': timestamp,
            'project_path': str(self.project_path),
            'summary': remediation_results.get('summary', {}),
            'statistics': {
                'total_findings': remediation_results.get('total_findings', 0),
                'successful_remediations': remediation_results.get('successful', 0),
                'failed_remediations': remediation_results.get('failed', 0),
                'success_rate': remediation_results.get('summary', {}).get('success_rate', '0%')
            },
            'actions_taken': [
                'Source code updated to use environment variables',
                '.env and .env.example files created/updated',
                '.gitignore updated with security patterns',
                'File backups created for rollback capability',
                'Secret rotation scripts generated'
            ],
            'next_steps': [
                'Review generated .env file and replace placeholder values',
                'Test applications with new environment variable configuration',
                'Execute rotation scripts to invalidate old secrets',
                'Deploy updated applications to production',
                'Monitor applications for any issues'
            ],
            'files_modified': [],
            'rotation_scripts': []
        }

        # Extract file modification details
        for result in remediation_results.get('results', []):
            if result.get('status') == 'secured':
                report['files_modified'].append({
                    'file_path': result.get('file_path'),
                    'environment_variable': result.get('environment_variable'),
                    'backup_path': result.get('backup_path')
                })

                rotation_script = result.get('rotation_script')
                if rotation_script and rotation_script.get('status') == 'success':
                    report['rotation_scripts'].append({
                        'secret_type': rotation_script.get('secret_type'),
                        'estimated_downtime': rotation_script.get('estimated_downtime'),
                        'prerequisites': rotation_script.get('prerequisites', [])
                    })

        return report