
import { InsecurePortSetting, Severity } from './types';

export const DEFAULT_INSECURE_PORTS: InsecurePortSetting[] = [
  // High Risk
  { port: 21, label: 'FTP', criticality: 'HIGH', whyInsecure: 'Cleartext credentials & data', enabled: true },
  { port: 23, label: 'Telnet', criticality: 'HIGH', whyInsecure: 'Cleartext remote login', enabled: true },
  { port: 25, label: 'SMTP', criticality: 'HIGH', whyInsecure: 'No encryption by default, abuse vector', enabled: true },
  { port: 69, label: 'TFTP', criticality: 'HIGH', whyInsecure: 'No authentication', enabled: true },
  { port: 110, label: 'POP3', criticality: 'HIGH', whyInsecure: 'Cleartext credentials', enabled: true },
  { port: 119, label: 'NNTP', criticality: 'HIGH', whyInsecure: 'Cleartext & legacy', enabled: true },
  { port: 137, label: 'NetBIOS NS', criticality: 'HIGH', whyInsecure: 'Windows enumeration', enabled: true },
  { port: 138, label: 'NetBIOS DGM', criticality: 'HIGH', whyInsecure: 'Lateral movement', enabled: true },
  { port: 139, label: 'NetBIOS SSN', criticality: 'HIGH', whyInsecure: 'SMB attacks', enabled: true },
  { port: 143, label: 'IMAP', criticality: 'HIGH', whyInsecure: 'Cleartext authentication', enabled: true },
  { port: 161, label: 'SNMP v1/v2', criticality: 'HIGH', whyInsecure: 'Weak auth, info disclosure', enabled: true },
  { port: 162, label: 'SNMP Trap', criticality: 'HIGH', whyInsecure: 'Data leakage', enabled: true },
  { port: 389, label: 'LDAP', criticality: 'HIGH', whyInsecure: 'Cleartext directory access', enabled: true },
  { port: 445, label: 'SMB', criticality: 'HIGH', whyInsecure: 'Ransomware, lateral movement', enabled: true },
  { port: 512, label: 'rexec', criticality: 'HIGH', whyInsecure: 'Remote command execution', enabled: true },
  { port: 513, label: 'rlogin', criticality: 'HIGH', whyInsecure: 'Trust-based auth', enabled: true },
  { port: 514, label: 'rsh', criticality: 'HIGH', whyInsecure: 'No auth, cleartext', enabled: true },
  { port: 2049, label: 'NFS', criticality: 'HIGH', whyInsecure: 'No encryption/auth by default', enabled: true },
  { port: 6000, label: 'X11', criticality: 'HIGH', whyInsecure: 'Remote desktop hijacking', enabled: true },
  
  // Medium Risk
  { port: 20, label: 'FTP Data', criticality: 'MEDIUM', whyInsecure: 'Same risks as FTP', enabled: true },
  { port: 22, label: 'SSH', criticality: 'MEDIUM', whyInsecure: 'Weak ciphers possible in legacy configs', enabled: true },
  { port: 37, label: 'Time', criticality: 'MEDIUM', whyInsecure: 'Information disclosure', enabled: true },
  { port: 53, label: 'DNS', criticality: 'MEDIUM', whyInsecure: 'Amplification attacks', enabled: true },
  { port: 80, label: 'HTTP', criticality: 'MEDIUM', whyInsecure: 'Cleartext web traffic', enabled: true },
  { port: 109, label: 'POP2', criticality: 'MEDIUM', whyInsecure: 'Obsolete & cleartext', enabled: true },
  { port: 179, label: 'BGP', criticality: 'MEDIUM', whyInsecure: 'Routing attacks if exposed', enabled: true },
  { port: 500, label: 'ISAKMP', criticality: 'MEDIUM', whyInsecure: 'VPN enumeration', enabled: true },
  { port: 1900, label: 'SSDP', criticality: 'MEDIUM', whyInsecure: 'Reflection attacks', enabled: true },
  { port: 3306, label: 'MySQL', criticality: 'MEDIUM', whyInsecure: 'Cleartext auth possible', enabled: true },
  { port: 3389, label: 'RDP', criticality: 'MEDIUM', whyInsecure: 'Brute force attacks', enabled: true },
  { port: 5900, label: 'VNC', criticality: 'MEDIUM', whyInsecure: 'Weak/no encryption', enabled: true },
  { port: 8080, label: 'HTTP Proxy', criticality: 'MEDIUM', whyInsecure: 'Often misconfigured', enabled: true },

  // Low Risk
  { port: 123, label: 'NTP', criticality: 'LOW', whyInsecure: 'Amplification if open', enabled: true },
  { port: 135, label: 'RPC', criticality: 'LOW', whyInsecure: 'Info leakage', enabled: true },
  { port: 636, label: 'LDAPS', criticality: 'LOW', whyInsecure: 'Secure if configured', enabled: true },
  { port: 989, label: 'FTPS Data', criticality: 'LOW', whyInsecure: 'Encrypted FTP', enabled: true },
  { port: 990, label: 'FTPS Control', criticality: 'LOW', whyInsecure: 'Encrypted FTP', enabled: true },
  { port: 993, label: 'IMAPS', criticality: 'LOW', whyInsecure: 'Encrypted IMAP', enabled: true },
  { port: 995, label: 'POP3S', criticality: 'LOW', whyInsecure: 'Encrypted POP3', enabled: true },
  { port: 1433, label: 'MSSQL', criticality: 'LOW', whyInsecure: 'Internal DB access risk', enabled: true },
  { port: 1521, label: 'Oracle DB', criticality: 'LOW', whyInsecure: 'Internal only - should not be routed', enabled: true },
  { port: 27017, label: 'MongoDB', criticality: 'LOW', whyInsecure: 'Secure if auth enabled', enabled: true },
];

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: 'bg-red-600 text-white',
  HIGH: 'bg-orange-500 text-white',
  MEDIUM: 'bg-yellow-500 text-black',
  LOW: 'bg-blue-500 text-white',
  INFORMATIONAL: 'bg-slate-500 text-white',
};

export const DEFAULT_MAPPINGS = [
  { field: 'id', synonyms: ['rule id', 'id', 'num', 'index', 'rule_id'] },
  { field: 'name', synonyms: ['rule name', 'name', 'label', 'description'] },
  { field: 'source', synonyms: ['source', 'src', 'source ip', 'source address', 'src_ip'] },
  { field: 'destination', synonyms: ['destination', 'dst', 'destination ip', 'dest address', 'dst_ip'] },
  { field: 'sourcePort', synonyms: ['source port', 'src port', 'sport'] },
  { field: 'destinationPort', synonyms: ['destination port', 'dest port', 'dport', 'service port', 'port'] },
  { field: 'protocol', synonyms: ['protocol', 'proto', 'ip protocol'] },
  { field: 'action', synonyms: ['action', 'permit', 'policy', 'rule_action'] },
  { field: 'direction', synonyms: ['direction', 'dir', 'flow'] },
  { field: 'enabled', synonyms: ['enabled', 'status', 'active', 'is_enabled'] },
  { field: 'description', synonyms: ['description', 'comment', 'notes'] },
];
