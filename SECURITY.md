# Security Policy

RealMythos works with security-sensitive artifacts, including vulnerability metadata, reasoning traces, PoC-oriented outputs, and reproducibility environments.

## Responsible Disclosure

Please do not disclose sensitive security issues through public GitHub issues.

Examples of sensitive reports include:

- A dataset record that enables active exploitation beyond the intended research context
- A reproducibility case that exposes a currently exploitable deployment
- Credentials, private tokens, or non-public paths included in an artifact
- A release artifact that appears to violate an upstream disclosure boundary
- Safety bypasses in release filtering or trace collection

Until a dedicated security contact is finalized, please contact the maintainers privately through the project owner's preferred channel.

## Public Issues

Public issues are appropriate for:

- Documentation bugs
- Broken links
- Missing metadata
- Non-sensitive dataset schema questions
- Reproducibility suggestions that do not expose active exploit details

## Intended Use

RealMythos is intended for security research, defensive evaluation, model alignment, and reproducible academic study.

It is not intended for unauthorized exploitation, offensive scanning, or automated vulnerability weaponization.
