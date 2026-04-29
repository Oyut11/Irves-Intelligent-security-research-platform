# Security Policy

## Supported Versions

| Version | Supported | Security Updates |
|---------|-----------|------------------|
| 1.0.x   | ✅ Yes    | Until 2.0.0 release |
| 0.9.x   | ⚠️ Security-only | Until 1.0.0 release |
| < 0.9   | ❌ No     | N/A |

## Reporting a Vulnerability

If you discover a security vulnerability in IRVES, please report it responsibly.

**Do NOT open a public issue.**

### How to Report

Send an email to: sorgilbat@gmail.com

Include the following information:
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Proof of concept (if applicable)
- Suggested fix (if known)

### What to Expect

- **Within 48 hours**: We will acknowledge receipt of your report
- **Within 7 days**: We will provide an initial assessment and estimated timeline
- **Before public disclosure**: We will work with you to coordinate a fix and release

### Disclosure Policy

We follow a **responsible disclosure** process:
1. Vulnerability is verified and triaged
2. Fix is developed in a private branch
3. Security release is prepared
4. Public disclosure is coordinated with the reporter
5. Credit is given to the reporter (if desired)

### Security Updates

Security updates are released as:
- **Patch releases** (e.g., 1.0.1) — Critical security fixes only
- **Minor releases** (e.g., 1.1.0) — Security fixes + new features
- **Major releases** (e.g., 2.0.0) — Security fixes + breaking changes

Users are encouraged to:
- Subscribe to GitHub releases for security notifications
- Monitor the [CHANGELOG.md](CHANGELOG.md) for security entries
- Update to the latest supported version promptly

## Security Best Practices for Users

### Deployment
- Use HTTPS in production (nginx + Let's Encrypt recommended)
- Set a strong `SECRET_KEY` in `.env` (use `generate_secret.py`)
- Do not commit `.env` files to version control
- Use PostgreSQL for production (not SQLite) if multi-user
- Keep dependencies updated (`pip install -U -r requirements.txt`)

### AI Provider Keys
- Rotate API keys regularly
- Use separate keys for development and production
- Monitor usage on provider dashboards
- Revoke compromised keys immediately

### Network Exposure
- Do not expose IRVES directly to the internet without SSL
- Use a reverse proxy (nginx) with proper security headers
- Implement rate limiting at the proxy level
- Restrict access via firewall if possible

### File Uploads
- APK uploads are limited to 500MB (configurable in nginx.conf)
- Uploaded files are stored in `~/.irves/projects` — ensure proper permissions
- Scan uploaded files with antivirus if processing untrusted sources

## Dependency Security

IRVES uses the following security practices:
- **Python dependencies**: Pinned versions in `requirements.txt`
- **Docker base images**: Use official, signed images
- **Regular updates**: Dependabot monitors for vulnerabilities
- **Security scanning**: CI/CD runs security checks on PRs

## PGP Key

For encrypted communication, use the project PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP key would be added here]
-----END PGP PUBLIC KEY BLOCK-----
```

Fingerprint: `[ADD FINGERPRINT]`

## Security Hall of Fame

We credit responsible security researchers who help make IRVES more secure:

| Date | Researcher | Vulnerability | CVE |
|------|------------|---------------|-----|
| TBD  | TBD        | TBD           | TBD |

## Questions?

For security-related questions that are not vulnerability reports, please open a GitHub discussion with the `security` label.
