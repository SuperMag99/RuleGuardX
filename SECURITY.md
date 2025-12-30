# Security Policy

## 🔒 Security Posture
**RuleGuardX** is built as an offline-first, browser-based security tool. It is a critical requirement of this project that no data is ever transmitted to external servers.

### Data Privacy
- **No Telemetry:** We do not track usage or collect metadata.
- **Local Processing:** CSV parsing, security analysis, and chart generation occur entirely within the client-side JavaScript execution context.
- **Persistence:** Configuration settings (like custom port matrices) are stored in your browser's `localStorage` and never synchronized.

## Reporting a Vulnerability
If you discover a security vulnerability within RuleGuardX (e.g., an XSS vector in the CSV parser or a logic flaw in the risk engine), please follow these steps:

1. **Do not open a public GitHub issue.**
2. Send a detailed report to the maintainers (or follow the project's specific contact instructions if available).
3. Include a Proof of Concept (PoC) and a sample (sanitized) CSV if the issue is data-dependent.

### Supported Versions
We only provide security updates for the latest version of the tool. Users are encouraged to always use the current `main` branch.

## 🛡️ Ethics & Responsibility
RuleGuardX is a **Read-Only** auditor. It does not possess the capability to modify firewall rules, interact with management APIs, or communicate with network hardware. Use this tool only on configurations you are authorized to audit.