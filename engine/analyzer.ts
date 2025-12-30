import { FirewallRule, AnalysisFinding, Severity, AnalysisResults, InsecurePortSetting } from '../types';

/**
 * SOC KNOWLEDGE BASE (OFFLINE)
 * Contains defensible risk explanations based on:
 * 1. MITRE ATT&CK Framework
 * 2. NIST SP 800-53 / 800-41
 * 3. CIS Critical Security Controls
 * 4. OWASP Top 10 / SANS Top 25
 * 5. CWE (Common Weakness Enumeration)
 */
const SECURITY_KNOWLEDGE_BASE = {
  ANY_ANY: {
    explanation: "Critical security control failure. Allowing 'ANY' source, destination, and service creates a 'Transparent Firewall' state. This violates NIST SP 800-53 AC-4 (Information Flow Enforcement) and is the primary vector for MITRE ATT&CK T1133 (External Remote Services). It provides zero resistance to automated reconnaissance and lateral movement.",
    recommendation: "Immediate Remediation Required: Deconstruct the rule into specific micro-segments. Implement explicit 'Allow' lists (CIS Control 4.4) for known-good IP ranges and services only."
  },
  ANY_SOURCE: {
    explanation: "Unrestricted Ingress Exposure. Source 'ANY' implies the rule is reachable from any point in the routed network (often the entire internet). According to SANS/CWE-284, improper access control leads to unauthorized access. This exposure is mapped to MITRE T1595 (Active Scanning) as it provides a target for global scanning botnets.",
    recommendation: "Restrict the source to specific authorized CIDR blocks or Geofenced IP ranges. Implement MFA-backed VPN for remote access (NIST AC-17)."
  },
  ANY_DESTINATION: {
    explanation: "Blast Radius Escalation. Destination 'ANY' permits traffic to potentially traverse into internal management subnets, sensitive database zones, or domain controllers. This bypasses the principle of 'Network Segmentation' (NIST SP 800-125B) and facilitates MITRE T1021 (Remote Services) lateral movement paths.",
    recommendation: "Narrow the destination to the specific IP address or host group required. Audit destination zones to ensure traffic doesn't bridge high-trust and low-trust boundaries."
  },
  LARGE_SUBNET: (size: number) => ({
    explanation: `Excessive Blast Radius (/${size}). A network segment this large (/16 - /22) typically contains hundreds or thousands of hosts. In an enterprise environment, this broad trust relationship facilitates MITRE T1046 (Network Service Discovery) and massive lateral movement (T1021). Large subnets violate the Zero Trust Architecture (ZTA) principle defined in NIST SP 800-207.`,
    recommendation: "Segment the network into smaller VLANs/Subnets (typically /24 or smaller). Use host-based firewalling or micro-segmentation to limit peer-to-peer communication within the subnet."
  }),
  PORT_SPECIFIC: {
    21: "FTP: Legacy cleartext protocol. Susceptible to MITRE T1557.002 (Adversary-in-the-Middle) and CWE-319. Credentials and data are transmitted in plaintext, violating NIST SP 800-52 requirements for protecting sensitive information.",
    23: "Telnet: Highly insecure administrative protocol. Replaced by SSH (NIST SP 800-53 IA-2). Plaintext transmission of management credentials allows easy interception via MITRE T1040 (Network Sniffing).",
    445: "SMB/CIFS: Extremely high risk for lateral movement. Associated with MITRE T1021.002 and historic ransomware strains like WannaCry (EternalBlue). CIS Control 12 recommends blocking SMB at network boundaries to prevent NTLM relay attacks and remote file execution.",
    3389: "RDP: Primary entry point for ransomware. Mapped to MITRE T1133. RDP exposure without NLA or MFA is a critical finding under CIS Control 4. Default configuration allows for brute-force attacks (T1110) and potential exploit of BlueKeep-style vulnerabilities.",
    22: "SSH: While secure, direct internet exposure is discouraged by CIS Benchmark 1.1. Brute-force (T1110) is common. Should be restricted to Jump Hosts (Bastions) only.",
    80: "HTTP: Unencrypted web traffic (CWE-319). Allows for session hijacking and credential theft (T1557). OWASP recommends enforcing HTTPS (TLS 1.2+) globally.",
    3306: "MySQL: Database exposure. Facilitates MITRE T1190 (Exploit Public-Facing Application) and T1534 (Internal Spearphishing for DB access). Direct network access to databases should never cross security zones.",
    1433: "MSSQL: High-value target for data exfiltration (MITRE T1020). Risk of SQL injection escalation if the listener is exposed to untrusted segments."
  } as Record<number, string>,
  HYGIENE: {
    SHADOWING: {
      explanation: "Rule Shadowing (NIST SP 800-41): A critical redundancy issue where a rule is entirely eclipsed by a preceding rule with identical or broader criteria. Shadowed rules are technically unreachable. Performance Impact: Every redundant rule increases the policy lookup latency (linear O(n) search), consuming CPU cycles and memory. Maintenance Impact: Shadowing creates 'Configuration Sprawl' and 'Technical Debt', making it difficult for auditors to determine the intended security posture and increasing the risk of accidental misconfiguration during policy updates.",
      recommendation: "Policy De-duplication: Remove the shadowed rule. Consolidate overlapping rules into single entries using Object Groups (IP Sets/Service Groups) to maintain a lean, high-performance policy base (CIS Control 12)."
    },
    CONFLICT: {
      explanation: "Policy Logic Conflict (Race Condition): Two rules cover the same traffic flow but mandate different actions (Permit vs Deny). While most firewalls use a 'First-Match' algorithm, conflicting rules indicate a lack of deterministic policy design. This ambiguity leads to 'Security Leakage' where a change in rule order accidentally grants unauthorized access. It violates the principle of 'Explicit Intent' and complicates incident response, forensic analysis, and compliance reporting.",
      recommendation: "Standardize Policy Order: Place 'Deny' rules for specific subnets above 'Allow' rules for broader segments (Ordered Filtering). Use an explicit 'Deny All' (Default Deny) at the end of each zone pair to enforce strict boundary control."
    },
    LATENT_RISK: {
      explanation: "Latent Exposure (Dormant High-Risk Rules): This rule is disabled but contains broad 'ANY' criteria or exposes administrative services. According to CIS Control 12, inactive rules should be purged periodically. Disabled rules are often 'temporarily' re-enabled during troubleshooting and forgotten, or leveraged by an adversary who has gained administrative control (MITRE T1562.001 - Impair Defenses) to quickly open backdoors without creating new rule logs.",
      recommendation: "Purge Policy Debt: If a rule has been disabled for more than 90 days (NIST best practice), it should be permanently deleted. Maintain a 'Clean Configuration' to minimize the attack surface available for manipulation."
    }
  }
};

const getCidrSize = (addr: string): number => {
  const clean = addr.trim().toLowerCase();
  if (clean === 'any' || clean === 'all' || clean === '0.0.0.0/0' || clean === '*') return 0;
  if (clean.includes('/')) {
    const parts = clean.split('/');
    const cidr = parseInt(parts[1], 10);
    return isNaN(cidr) ? 32 : cidr;
  }
  return 32;
};

const parsePorts = (portStr: string): number[] => {
  if (!portStr) return [];
  const clean = portStr.toString().trim().toLowerCase();
  if (clean === 'any' || clean === 'all' || clean === '*' || clean === '0-65535') return [-1];
  
  const parts = clean.split(/[,\s]+/);
  const result: number[] = [];
  
  parts.forEach(p => {
    if (p.includes('-')) {
      const [start, end] = p.split('-').map(x => parseInt(x.trim(), 10));
      if (!isNaN(start) && !isNaN(end)) {
        for (let i = start; i <= end; i++) result.push(i);
      }
    } else {
      const parsed = parseInt(p, 10);
      if (!isNaN(parsed)) result.push(parsed);
    }
  });
  
  return result;
};

export const analyzeRules = (rules: FirewallRule[], portSettings: InsecurePortSetting[]): AnalysisResults => {
  const findings: AnalysisFinding[] = [];
  const hygiene: AnalysisFinding[] = [];

  const activeInsecurePorts = new Map<number, InsecurePortSetting>();
  portSettings.filter(s => s.enabled).forEach(s => activeInsecurePorts.set(s.port, s));

  rules.forEach((rule, index) => {
    const ports = parsePorts(rule.destinationPort);
    const srcCidr = getCidrSize(rule.source);
    const dstCidr = getCidrSize(rule.destination);
    const isAllow = rule.action === 'ALLOW';
    const hasAnyPort = ports.includes(-1);

    // 1. ANY Rule Logic (Nuanced Severity)
    const isAnySource = srcCidr === 0;
    const isAnyDest = dstCidr === 0;
    const isAnyProto = rule.protocol === 'ANY';

    if (isAllow && (isAnySource || isAnyDest || isAnyProto || hasAnyPort)) {
      let explanation = "";
      let recommendation = "";
      let severity: Severity = 'MEDIUM';
      let score = 50;

      const anyDimensions = (isAnySource ? 1 : 0) + (isAnyDest ? 1 : 0) + (hasAnyPort ? 1 : 0) + (isAnyProto ? 0.5 : 0);
      
      if (anyDimensions >= 3) {
        severity = 'CRITICAL';
        score = 100;
        explanation = SECURITY_KNOWLEDGE_BASE.ANY_ANY.explanation;
        recommendation = SECURITY_KNOWLEDGE_BASE.ANY_ANY.recommendation;
      } else if (isAnySource) {
        severity = 'HIGH';
        score = 85;
        explanation = SECURITY_KNOWLEDGE_BASE.ANY_SOURCE.explanation;
        recommendation = SECURITY_KNOWLEDGE_BASE.ANY_SOURCE.recommendation;
      } else if (isAnyDest) {
        severity = 'HIGH';
        score = 80;
        explanation = SECURITY_KNOWLEDGE_BASE.ANY_DESTINATION.explanation;
        recommendation = SECURITY_KNOWLEDGE_BASE.ANY_DESTINATION.recommendation;
      } else {
        severity = 'MEDIUM';
        score = 60;
        explanation = `Broad protocol or port access ('ANY') detected. This increases the attack surface for specialized payloads and facilitates T1046 (Network Service Discovery).`;
        recommendation = "Restrict the rule to only the required ports and protocols (CIS Control 4.4).";
      }

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: 'Excessive Exposure',
        score: score,
        severity: severity,
        explanation,
        recommendation
      });
    }

    // 2. Subnet Scope Analysis (Numerical)
    if (isAllow) {
      if (srcCidr <= 16 && srcCidr > 0) {
        const kb = SECURITY_KNOWLEDGE_BASE.LARGE_SUBNET(srcCidr);
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: 'Subnet Scope',
          score: 80,
          severity: srcCidr <= 8 ? 'CRITICAL' : 'HIGH',
          explanation: kb.explanation,
          recommendation: kb.recommendation
        });
      } else if (srcCidr >= 17 && srcCidr <= 22) {
        const kb = SECURITY_KNOWLEDGE_BASE.LARGE_SUBNET(srcCidr);
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: 'Subnet Scope',
          score: 60,
          severity: 'HIGH',
          explanation: kb.explanation,
          recommendation: kb.recommendation
        });
      }
    }

    // 3. Insecure Ports (Strict Mapping)
    if (isAllow) {
      ports.forEach(p => {
        if (p === -1) return;
        const setting = activeInsecurePorts.get(p);
        if (setting) {
          const detailedRisk = SECURITY_KNOWLEDGE_BASE.PORT_SPECIFIC[p] || `Protocol/Port ${p} is flagged as insecure or high-risk for enterprise environments. Access to this port increases the threat profile of the host and facilitates potential MITRE ATT&CK techniques.`;
          
          findings.push({
            ruleId: rule.id,
            ruleName: rule.name,
            category: 'Insecure Port',
            score: setting.criticality === 'CRITICAL' ? 100 : setting.criticality === 'HIGH' ? 90 : 60,
            severity: setting.criticality,
            explanation: `Service Identity: ${setting.label} (Port ${p}). ${detailedRisk} Reference: ${setting.whyInsecure}.`,
            recommendation: `Transition to secure alternatives (e.g., replace FTP with SFTP, Telnet with SSH). If the service is required, restrict access to a specific 'Trusted Admin' subnet and implement deep packet inspection (DPI).`
          });
        }
      });
    }

    // 4. Policy Hygiene & Correlation (Set Analysis)
    const shadowedBy = rules.slice(0, index).find(prev => 
      prev.enabled &&
      prev.action === rule.action &&
      (prev.source === rule.source || prev.source.toLowerCase() === 'any') &&
      (prev.destination === rule.destination || prev.destination.toLowerCase() === 'any') &&
      (prev.protocol === rule.protocol || prev.protocol === 'ANY') &&
      (prev.destinationPort === rule.destinationPort || prev.destinationPort.toLowerCase() === 'any')
    );

    if (shadowedBy && rule.enabled) {
      hygiene.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: 'Policy Hygiene',
        score: 20,
        severity: 'INFORMATIONAL',
        explanation: `${SECURITY_KNOWLEDGE_BASE.HYGIENE.SHADOWING.explanation} This specific rule is eclipsed by Rule ID: ${shadowedBy.id}.`,
        recommendation: SECURITY_KNOWLEDGE_BASE.HYGIENE.SHADOWING.recommendation
      });
    }

    const conflicting = rules.slice(0, index).find(prev => 
      prev.enabled &&
      prev.action !== rule.action &&
      prev.source === rule.source &&
      prev.destination === rule.destination &&
      prev.destinationPort === rule.destinationPort
    );

    if (conflicting && rule.enabled) {
      hygiene.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: 'Correlation Error',
        score: 50,
        severity: 'MEDIUM',
        explanation: `${SECURITY_KNOWLEDGE_BASE.HYGIENE.CONFLICT.explanation} A direct action conflict exists with Rule ID: ${conflicting.id}.`,
        recommendation: SECURITY_KNOWLEDGE_BASE.HYGIENE.CONFLICT.recommendation
      });
    }

    if (!rule.enabled && isAllow) {
      if (srcCidr === 0 || hasAnyPort) {
        hygiene.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: 'Policy Hygiene',
          score: 40,
          severity: 'LOW',
          explanation: SECURITY_KNOWLEDGE_BASE.HYGIENE.LATENT_RISK.explanation,
          recommendation: SECURITY_KNOWLEDGE_BASE.HYGIENE.LATENT_RISK.recommendation
        });
      }
    }
  });

  return {
    rules,
    findings,
    hygiene,
    summary: {
      totalRules: rules.length,
      enabledRules: rules.filter(r => r.enabled).length,
      criticalFindings: findings.filter(f => f.severity === 'CRITICAL').length,
      highFindings: findings.filter(f => f.severity === 'HIGH').length,
      mediumFindings: findings.filter(f => f.severity === 'MEDIUM').length,
      lowFindings: findings.filter(f => f.severity === 'LOW').length,
      averageRiskScore: findings.length > 0 ? Math.round(findings.reduce((a, b) => a + b.score, 0) / findings.length) : 0
    }
  };
};