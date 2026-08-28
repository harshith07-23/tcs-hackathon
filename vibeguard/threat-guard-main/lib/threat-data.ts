export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface Metric {
  label: string
  value: string
  delta: string
  trend: 'up' | 'down'
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
