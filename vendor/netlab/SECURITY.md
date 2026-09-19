# Security policy

## Reporting a vulnerability

Please use GitHub private vulnerability reporting for this repository. Do not
open a public issue for vulnerabilities, credentials, unpublished hardware
details or vendor-license concerns.

Include the affected commit, component, reproduction conditions, expected
impact and whether real hardware is required. Maintainers will acknowledge a
complete report as soon as practical and coordinate disclosure after a fix is
available.

## Supported surface

Security fixes target the current `main` branch. This experimental project does
not currently publish long-term-support branches or production security SLAs.

## Repository hygiene

Never commit private keys, tokens, passwords, `.env` files, live topology,
vendor SDK content, firmware or prebuilt runtime bundles. The public-surface
check is a guardrail, not a substitute for reviewing every contribution.
