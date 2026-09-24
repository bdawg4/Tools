# Active Directory Automation

Central repository for Active Directory engineering automation,
auditing, health checks, operational tooling, and supporting
documentation.

## Repository Structure

- `scripts/` - Operational PowerShell scripts
- `modules/` - Reusable PowerShell modules
- `tests/` - Automated tests and validation
- `config/` - Non-sensitive configuration
- `docs/` - Architecture, standards, and runbooks

## Contribution Workflow

Changes to the main branch must be made through a feature branch
and submitted through a Pull Request.

## Security

Do not commit:

- Passwords
- API keys
- Tokens
- Certificates with private keys
- Production credentials
- Sensitive AD exports
- NTDS data
- Production secrets
