# Contributing to secuditor-scripts

Thank you for your interest in contributing to **secuditor-scripts**!  
This repository contains a partial collection of open-source Python scripts developed as part of the Secuditor project, focused on **Windows security diagnostics and operational security (OpSec)**.

Contributions are welcome, as long as they align with the project’s goals and standards.

---

## Scope of Contributions

This repository is intended for:

- Defensive and diagnostic **security-related Python scripts**
- Windows-focused security checks, audits, or helpers
- Standalone scripts that may later integrate into Secuditor
- Improvements, bug fixes, or refactoring of existing scripts
- Documentation improvements

### Out of Scope
Please **do not submit**:

- Malware, exploit code, or weaponized payloads
- Offensive tools intended for unauthorized access
- Obfuscated or intentionally malicious code
- Scripts that encourage illegal or unethical use

All contributions must follow **ethical and defensive security principles**.

---

## Contribution Guidelines

### 1. Code Style
- Use **Python 3**
- Follow **PEP 8** where practical
- Keep scripts readable and well-commented
- Prefer standard libraries when possible
- Avoid unnecessary external dependencies

### 2. Script Requirements
Each script should:

- Be **self-contained**
- Include a short header comment explaining its purpose
- Handle errors gracefully
- Avoid destructive actions by default
- Clearly indicate if **administrator privileges** are required

Example header:

```python
"""
sp_example.py
Description: Checks example security configuration on Windows
Requires: Admin privileges
"""
