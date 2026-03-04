# Contributing to Git Security Audit System

Thank you for considering contributing to the Git Security Audit System! 🎉

## 🚀 Quick Start

1. **Fork** the repository
2. **Clone** your fork
3. **Create** a feature branch
4. **Make** your changes
5. **Test** thoroughly
6. **Submit** a pull request

## 📋 Development Setup

### Prerequisites
- Python 3.8+
- Git
- Linux/macOS (Windows WSL)

### Environment Setup
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/git-security-audit-system.git
cd git-security-audit-system

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest flake8 black mypy

# Setup security tools
./setup_scanners_local.sh
```

### Running Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html

# Run specific test
python -m pytest tests/test_scanner_engine.py::TestDetectionEngine::test_gitleaks_scan
```

### Code Quality
```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy .

# All quality checks
black . && flake8 . && mypy . && python -m pytest
```

## 🎯 Areas for Contribution

### 🔍 **Security Tools Integration**
- Add new security scanning tools
- Improve existing tool configurations
- Enhance detection patterns

### 📊 **Reporting & Analysis**
- New report formats (PDF, SARIF, etc.)
- Enhanced risk scoring algorithms
- Better false-positive detection

### 🤖 **Automation & CI/CD**
- GitHub Actions integration
- Docker containerization improvements
- Cloud deployment options

### 🔧 **Platform Support**
- Windows native support
- Additional Git hosting platforms
- Mobile/tablet reporting interfaces

### 📚 **Documentation**
- Tutorials and guides
- Video demonstrations
- API documentation

## 📝 Contribution Guidelines

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and small

### Git Workflow
```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make commits with clear messages
git commit -m "feat: add SARIF report format support

- Implement SARIF 2.1.0 schema compatibility
- Add command line option for SARIF output
- Include proper tool identification metadata
- Update documentation with SARIF examples"

# Push to your fork
git push origin feature/your-feature-name

# Create pull request
```

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test additions/changes
- `chore:` Build/maintenance tasks

### Pull Request Process

1. **Update Documentation**: Ensure README.md and other docs reflect your changes
2. **Add Tests**: New features must include appropriate tests
3. **Update Changelog**: Add entry to CHANGELOG.md (if exists)
4. **Check CI**: Ensure all automated checks pass
5. **Request Review**: Tag relevant maintainers

## 🧪 Testing Guidelines

### Test Structure
```bash
tests/
├── unit/                   # Unit tests for individual components
├── integration/           # Integration tests for workflows
├── fixtures/             # Test data and configurations
└── conftest.py          # Pytest configuration
```

### Writing Tests
```python
# Example test structure
def test_scanner_integration():
    """Test scanner integration with real repositories."""
    # Arrange
    test_repo = create_test_repository()
    scanner = DetectionEngine()

    # Act
    results = scanner.scan_repository(test_repo)

    # Assert
    assert len(results) > 0
    assert all('file_path' in r for r in results)
```

### Test Data
- Use fixture files for test data
- Never include real secrets in tests
- Use predictable, sanitized test repositories

## 🔒 Security Considerations

### Sensitive Data
- **Never** commit real secrets or credentials
- Use placeholder values in examples
- Sanitize test data thoroughly

### Security Reviews
- All security-related PRs require extra review
- Include threat model considerations
- Document security implications

## 📖 Documentation Standards

### Code Documentation
```python
def analyze_findings(self, raw_findings: List[Dict]) -> List[SecurityFinding]:
    """
    Analyze and correlate security findings from multiple tools.

    Args:
        raw_findings: List of raw findings from security scanners

    Returns:
        List of processed SecurityFinding objects with risk scores

    Raises:
        AnalysisError: If correlation analysis fails
    """
```

### User Documentation
- Use clear, actionable language
- Include code examples
- Add troubleshooting sections
- Test all documented procedures

## 🐛 Bug Reports

### Before Reporting
- Search existing issues for duplicates
- Test with the latest version
- Gather detailed reproduction steps

### Bug Report Template
```markdown
**Bug Description**
Brief description of the issue

**Steps to Reproduce**
1. Step one
2. Step two
3. Step three

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: [e.g., Ubuntu 20.04]
- Python: [e.g., 3.9.2]
- Version: [e.g., v1.2.0]

**Additional Context**
Screenshots, logs, etc.
```

## 💡 Feature Requests

### Feature Request Template
```markdown
**Feature Description**
Clear description of the proposed feature

**Use Case**
Why is this feature needed?

**Proposed Solution**
How should this feature work?

**Alternatives Considered**
Other approaches considered

**Additional Context**
Mockups, examples, etc.
```

## 🏆 Recognition

Contributors will be recognized in:
- README.md acknowledgments
- Release notes
- GitHub contributor statistics

### Hall of Fame
Outstanding contributors may be invited to become:
- **Collaborators**: Triage issues and review PRs
- **Maintainers**: Full repository access and release management

## 📞 Getting Help

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Pull Request Reviews**: Code-specific feedback

### Response Times
- **Issues**: Response within 48 hours
- **Pull Requests**: Initial review within 72 hours
- **Security Issues**: Immediate attention

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Thank You

Every contribution makes this project better! Whether it's:
- Reporting bugs
- Suggesting features
- Writing documentation
- Submitting code
- Testing and feedback

**Your efforts help keep repositories secure for everyone!** 🔒✨

---

*Happy contributing!* 🚀