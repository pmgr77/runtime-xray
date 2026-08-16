# runtime-xray
Open-source security posture analyzer for compiled binaries. See what an attacker can learn from your application at runtime.

## Security Checks
RuntimeXRay currently performs the following static checks:
- **Hardening checks**: NX, PIE, RELRO, Stack Canary
- **Dangerous API detection**: identifies imported functions known to be insecure, with CWE references and recommendations.

For detailed explanations, see [docs/security_checks.md](docs/security_checks.md).