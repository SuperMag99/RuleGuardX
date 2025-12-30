
export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'ANY' | 'OTHER';
export type Action = 'ALLOW' | 'DENY' | 'OTHER';
export type Direction = 'INBOUND' | 'OUTBOUND' | 'INTERNAL' | 'UNKNOWN';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface InsecurePortSetting {
  port: number;
  label: string;
  criticality: Severity;
  whyInsecure: string;
  enabled: boolean;
}

export interface FirewallRule {
  id: string;
  name: string;
  source: string;
  destination: string;
  sourcePort: string;
  destinationPort: string;
  service: string;
  protocol: Protocol;
  action: Action;
  direction: Direction;
  zone?: string;
  enabled: boolean;
  description?: string;
  originalRow: any;
}

export interface AnalysisFinding {
  ruleId: string;
  ruleName: string;
  category: 'Insecure Port' | 'Excessive Exposure' | 'Subnet Scope' | 'Protocol Risk' | 'Policy Hygiene' | 'Correlation Error';
  score: number;
  severity: Severity;
  explanation: string;
  recommendation: string;
}

export interface AnalysisResults {
  rules: FirewallRule[];
  findings: AnalysisFinding[];
  hygiene: AnalysisFinding[];
  summary: {
    totalRules: number;
    enabledRules: number;
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    averageRiskScore: number;
  };
}

export type FilterField = 
  | 'id' | 'name' | 'source' | 'destination' | 'destinationPort' | 'protocol' 
  | 'action' | 'direction' | 'description' | 'severity' | 'category';

export type FilterOperator = 
  | 'CONTAINS' | 'NOT_CONTAINS' | 'EQUALS' | 'NOT_EQUALS' 
  | 'STARTS_WITH' | 'ENDS_WITH' | 'GREATER_THAN' | 'LESS_THAN';

export interface FilterClause {
  id: string;
  field: FilterField;
  operator: FilterOperator;
  value: string;
  logicalOperator: 'AND' | 'OR'; // New: per-clause logic
}

export interface FilterState {
  clauses: FilterClause[];
  quickSearch: string;
}

export interface ColumnMapping {
  id: string;
  name: string;
  source: string;
  destination: string;
  sourcePort: string;
  destinationPort: string;
  protocol: string;
  action: string;
  direction: string;
  enabled: string;
  description: string;
}
