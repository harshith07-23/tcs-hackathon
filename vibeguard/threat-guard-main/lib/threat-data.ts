export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type NodeStatus = 'secure' | 'monitored' | 'compromised'

export interface Metric {
  label: string
  value: string
  delta: string
  trend: 'up' | 'down'
}

export interface ArchNode {
  id: string
  label: string
  kind: string
  x: number
  y: number
  status: NodeStatus
}

export interface ArchEdge {
  from: string
  to: string
  /** whether an active threat is traversing this link */
  active?: boolean
}

export interface Vulnerability {
  id: string
  cve: string
  title: string
  asset: string
  severity: Severity
  cvss: number
  vector: string
  detected: string
  status: 'active' | 'contained' | 'investigating'
  description: string
}

export interface ReportDetail {
  id: string
  project_name: string
  scan_date: string
  overall_score: number
  security_posture: string
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  findings: ApiFinding[]
  scan_metadata: {
    total_files: number
    python_files: number
    javascript_files: number
    config_files: number
    detected_frameworks: string[]
    scan_duration: number
  } | null
}

export interface ApiFinding {
  id: string
  title: string
  category: string
  severity: string
  file_path: string
  line_number: number | null
  description: string | null
  status: string
  created_at: string
}

export function toVulnerability(finding: ApiFinding): Vulnerability {
  const severity = finding.severity.toLowerCase() as Severity
  const cvssBySeverity: Record<Severity, number> = {
    critical: 9.5,
    high: 7.5,
    medium: 5,
    low: 2.5,
  }
  const status = finding.status === 'FIXED' || finding.status === 'FALSE_POSITIVE'
    ? 'contained'
    : finding.status === 'IGNORED'
      ? 'investigating'
      : 'active'

  return {
    id: finding.id,
    cve: finding.category.toUpperCase(),
    title: finding.title,
    asset: `${finding.file_path}${finding.line_number ? `:${finding.line_number}` : ''}`,
    severity,
    cvss: cvssBySeverity[severity] ?? 5,
    vector: finding.category,
    detected: new Date(finding.created_at).toLocaleString(),
    status,
    description: finding.description ?? 'No description provided.',
  }
}

export const riskScore = 78

export const metrics: Metric[] = [
  { label: 'Active Threats', value: '14', delta: '+3', trend: 'up' },
  { label: 'Assets Monitored', value: '212', delta: '+2', trend: 'up' },
  { label: 'Mean Time to Detect', value: '4.2m', delta: '-38s', trend: 'down' },
  { label: 'Patched (24h)', value: '31', delta: '+11', trend: 'up' },
]

// Coordinates are on a 0-100 viewBox grid.
export const archNodes: ArchNode[] = [
  { id: 'wan', label: 'Edge Gateway', kind: 'ingress', x: 12, y: 50, status: 'monitored' },
  { id: 'waf', label: 'WAF / Proxy', kind: 'security', x: 30, y: 28, status: 'secure' },
  { id: 'lb', label: 'Load Balancer', kind: 'network', x: 30, y: 72, status: 'secure' },
  { id: 'api', label: 'API Cluster', kind: 'compute', x: 52, y: 30, status: 'compromised' },
  { id: 'auth', label: 'Auth Service', kind: 'identity', x: 52, y: 66, status: 'monitored' },
  { id: 'db', label: 'Primary DB', kind: 'data', x: 76, y: 40, status: 'compromised' },
  { id: 'cache', label: 'Cache Layer', kind: 'data', x: 76, y: 70, status: 'secure' },
  { id: 'vault', label: 'Secrets Vault', kind: 'identity', x: 90, y: 54, status: 'monitored' },
]

export const archEdges: ArchEdge[] = [
  { from: 'wan', to: 'waf' },
  { from: 'wan', to: 'lb' },
  { from: 'waf', to: 'api', active: true },
  { from: 'lb', to: 'auth' },
  { from: 'api', to: 'auth' },
  { from: 'api', to: 'db', active: true },
  { from: 'auth', to: 'db' },
  { from: 'auth', to: 'cache' },
  { from: 'db', to: 'vault' },
  { from: 'cache', to: 'vault' },
]

export const vulnerabilities: Vulnerability[] = [
  {
    id: 'v1',
    cve: 'CVE-2025-31842',
    title: 'Unauthenticated RCE in API request parser',
    asset: 'API Cluster · api-prod-03',
    severity: 'critical',
    cvss: 9.8,
    vector: 'AV:N/AC:L/PR:N/UI:N',
    detected: '3 min ago',
    status: 'active',
    description:
      'A malformed multipart payload allows arbitrary command execution on the ingest workers. Active exploitation observed from 3 external IPs.',
  },
  {
    id: 'v2',
    cve: 'CVE-2025-29017',
    title: 'SQL injection via analytics filter',
    asset: 'Primary DB · pg-cluster-1',
    severity: 'critical',
    cvss: 9.1,
    vector: 'AV:N/AC:L/PR:L/UI:N',
    detected: '12 min ago',
    status: 'investigating',
    description:
      'Improper sanitization of the date-range filter permits blind SQL injection against the reporting replica, exposing session tables.',
  },
  {
    id: 'v3',
    cve: 'CVE-2025-27788',
    title: 'Session fixation in auth token refresh',
    asset: 'Auth Service · auth-edge',
    severity: 'high',
    cvss: 8.2,
    vector: 'AV:N/AC:H/PR:N/UI:R',
    detected: '41 min ago',
    status: 'contained',
    description:
      'Refresh tokens are not rotated on privilege escalation, enabling reuse of a captured token across elevated sessions.',
  },
  {
    id: 'v4',
    cve: 'CVE-2025-26510',
    title: 'Outdated TLS cipher suite negotiated',
    asset: 'Edge Gateway · gw-eu-west',
    severity: 'high',
    cvss: 7.4,
    vector: 'AV:N/AC:H/PR:N/UI:N',
    detected: '1 h ago',
    status: 'active',
    description:
      'Gateway falls back to TLS 1.1 with CBC ciphers under load, exposing traffic to downgrade and padding-oracle attacks.',
  },
]
