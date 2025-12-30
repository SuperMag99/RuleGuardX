# RuleGuardX 🛡️

**RuleGuardX** is a high-performance, enterprise-grade offline firewall rules auditor. Designed for Network Security Architects and Blue-Team Automation Engineers, it evaluates firewall configuration exports (CSV) to identify misconfigurations, excessive exposure, and lateral-movement risks using specialized security logic.

![FootprintX Hero Screenshot](https://github.com/SuperMag99/RuleGuardX/blob/main/screenshot/1.png)
![FootprintX Hero Screenshot](https://github.com/SuperMag99/RuleGuardX/blob/main/screenshot/2.png)

---

## 🎯 Project Overview
RuleGuardX provides a defensible risk assessment of firewall rules by correlating policy logic against real-world attack patterns. Unlike basic auditors, RuleGuardX performs context-aware evaluation of services, protocols, and network scopes.

### Core Analysis Capabilities:
- **High-Risk Service Mapping:** Identifies exposure of administrative (RDP, SSH, WinRM) and weak (Telnet, FTP, SMB) protocols.
- **Excessive Exposure Logic:** Specifically targets `ANY/ANY/ANY` rules and escalates severity based on destination sensitivity.
- **Subnet Scope Analysis:** Numerically evaluates CIDR sizes (e.g., /8, /16 vs /24) to flag broad trust relationships.
- **Policy Hygiene:** Detects shadowed rules, logic conflicts (Allow vs Deny), and latent risks in disabled policies.
- **Correlation Engine:** Analyzes rules as a set to find overlapping or redundant controls.

---

## ⚠️ Hard Constraints & Security
- **❌ No APIs / No Cloud:** All analysis is performed locally in your browser.
- **❌ No Vendor Lock-in:** Agnostic CSV ingestion with dynamic field mapping.
- **✅ Read-Only:** The tool analyzes policy exports only; it cannot make changes to your infrastructure.
- **✅ Zero Data Leakage:** Your firewall configuration never leaves your machine.

---

## 📊 Risk Scoring Model
RuleGuardX assigns a **Risk Score (0–100)** to every rule based on:
- **Critical (100):** Internet-facing RDP/SSH, ANY/ANY Allow rules.
- **High (80+):** Large subnet exposure, legacy plaintext protocols (Telnet/FTP).
- **Medium (50-70):** Logical conflicts, broad internal-to-internal rules.
- **Low/Info:** Technical debt, shadowed rules, and documentation gaps.

*Logic derived from NIST SP 800-41, MITRE ATT&CK, and CIS Critical Security Controls.*

---

## 🚀 Quick Start & Installation

To get RuleGuardX running on your local machine, follow these steps (CMD or PowerShell):

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/SuperMag99/RuleGuardX.git
   cd RuleGuardX
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Run the Application**:
   ```bash
   npm run dev
   ```

### Usage
1. **Export:** Export your firewall policy to CSV (compatible with Palo Alto, Fortinet, Cisco, Check Point, etc.).
2. **Import:** Drag and drop the CSV into the **Import** tab.
3. **Map:** Verify the column mappings (RuleGuardX auto-detects most standard headers).
4. **Analyze:** Review the Dashboard for high-level risk metrics and drill down into the **Findings** tab for remediation guidance.

---

## 📄 Output Artifacts
The tool generates localized reports for audit documentation:
- `firewall_findings.json`: Full technical breakdown of all risks.
- `summary_report.txt`: High-level executive summary of the policy posture.
- **Visual Charts:** Real-time generation of risk distribution and port exposure maps.

---

## ⚖️ License & Copyright
Copyright (c) 2025 RuleGuardX.

This project is licensed under the **MIT License**.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

**Security & Ethics Notice:** This tool is intended for authorized security audits only. RuleGuardX performs offline analysis and does not interact with live network devices.

---

## 👤 Maintainer
**SuperMag99**  
🔗 GitHub: [SuperMag99](https://github.com/SuperMag99)  
🔗 LinkedIn: [mag99](https://www.linkedin.com/in/mag99/)
