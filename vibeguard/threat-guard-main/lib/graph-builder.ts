/**
 * graph-builder.ts
 *
 * Builds a dynamic architecture graph from actual vulnerability findings.
 * Every node represents a security area that has at least one finding.
 * Edges reflect logical architectural relationships between co-present areas.
 *
 * Key guarantees:
 *   - Deterministic: same input always produces the same graph.
 *   - No hardcoded nodes: areas are derived from findings only.
 *   - No randomization: positions are computed from sorted area names.
 */

import type { ApiFinding } from '@/lib/threat-data'

/* ------------------------------------------------------------------ */
/*  Public types                                                       */
/* ------------------------------------------------------------------ */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export interface GraphNode {
  id: string
  label: string
  kind: string
  x: number
  y: number
  vulnerabilityCount: number
  highestSeverity: SeverityLevel
  vulnerabilities: string[]   // finding IDs
  files: string[]             // unique file paths
}

export interface GraphEdge {
  from: string
  to: string
  active: boolean             // true when either endpoint is CRITICAL or HIGH
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

/* ------------------------------------------------------------------ */
/*  Security area taxonomy                                             */
/* ------------------------------------------------------------------ */

const SECURITY_AREAS = [
  'Frontend',
  'Backend',
  'API',
  'Database',
  'Authentication',
  'Authorization',
  'Configuration',
  'Dependencies',
  'Cryptography',
  'Secrets',
  'File System',
  'Network',
  'Infrastructure',
] as const

export type SecurityArea = (typeof SECURITY_AREAS)[number]

/** Short machine-readable kind shown beneath each node label. */
const AREA_KIND: Record<SecurityArea, string> = {
  Frontend: 'ui',
  Backend: 'compute',
  API: 'interface',
  Database: 'data',
  Authentication: 'identity',
  Authorization: 'access',
  Configuration: 'config',
  Dependencies: 'supply-chain',
  Cryptography: 'crypto',
  Secrets: 'secrets',
  'File System': 'storage',
  Network: 'network',
  Infrastructure: 'infra',
}

/* ------------------------------------------------------------------ */
/*  File-path classification rules                                     */
/* ------------------------------------------------------------------ */

interface PathRule {
  /**
   * Patterns to match against the lowercase file path.
   * Patterns ending with '/' are directory indicators.
   * Patterns starting with '.' are extension indicators.
   * All other patterns are matched as substrings.
   */
  patterns: string[]
  area: SecurityArea
}

const PATH_RULES: PathRule[] = [
  // Frontend — UI frameworks, components, client-side code
  { patterns: ['.jsx', '.tsx', '.vue', '.svelte', 'src/components/', 'src/pages/', 'src/views/', 'frontend/', 'client/', 'public/'], area: 'Frontend' },
  // Backend — server-side application code
  { patterns: ['backend/', 'server/', 'controllers/', 'handlers/', 'middleware/'], area: 'Backend' },
  // API — explicit API layers
  { patterns: ['api/', 'endpoints/', 'graphql/', 'rest/', 'swagger', 'openapi'], area: 'API' },
  // Database — schema, queries, migrations
  { patterns: ['.sql', 'database/', 'db/', 'migrations/', 'schema/', 'queries/'], area: 'Database' },
  // Authentication — dedicated auth directories/files
  { patterns: ['auth/', 'authentication/', 'oauth/', 'jwt/'], area: 'Authentication' },
  // Authorization — dedicated authz directories
  { patterns: ['permissions/', 'roles/', 'policies/', 'rbac/', 'acl/'], area: 'Authorization' },
  // Configuration — config files and directories
  { patterns: ['.env', 'config/', '.yml', '.yaml', '.toml', '.ini', 'docker-compose', 'dockerfile', 'settings.', '.cfg'], area: 'Configuration' },
  // Dependencies — package manifests and lockfiles
  { patterns: ['package.json', 'package-lock', 'requirements.txt', 'pipfile', 'pom.xml', 'build.gradle', 'gemfile', 'cargo.toml', 'go.mod', 'yarn.lock'], area: 'Dependencies' },
  // Cryptography — dedicated crypto modules
  { patterns: ['crypto/', 'encryption/', 'certs/', 'ssl/', 'tls/', '.pem', '.crt'], area: 'Cryptography' },
  // Secrets — secrets vaults, key stores
  { patterns: ['secrets/', 'vault/', '.key', 'credentials/'], area: 'Secrets' },
  // File System — file handling modules
  { patterns: ['upload/', 'download/', 'storage/', 'media/'], area: 'File System' },
  // Network — networking modules
  { patterns: ['network/', 'socket/', 'proxy/', 'websocket/'], area: 'Network' },
  // Infrastructure — deployment and CI/CD
  { patterns: ['k8s/', 'kubernetes/', 'terraform/', 'deploy/', 'ci/', '.github/', 'ansible/', 'helm/'], area: 'Infrastructure' },
]

/* ------------------------------------------------------------------ */
/*  Category / title classification rules                              */
/*                                                                     */
/*  These use word-boundary matching: the pattern must appear as a     */
/*  standalone word or recognizable token, not as a random substring.  */
/* ------------------------------------------------------------------ */

interface CategoryRule {
  /**
   * Each pattern is matched using a word-boundary-aware check against
   * the finding's category and title (lowercased).
   */
  patterns: string[]
  area: SecurityArea
}

const CATEGORY_RULES: CategoryRule[] = [
  // Frontend — client-side vulnerabilities
  { patterns: ['xss', 'cross-site scripting', 'dom injection', 'csrf', 'cross-site request forgery', 'open redirect', 'clickjacking'], area: 'Frontend' },
  // Backend — server-side execution vulnerabilities
  { patterns: ['command injection', 'rce', 'remote code execution', 'code execution', 'deserialization', 'server-side request forgery'], area: 'Backend' },
  // API — interface-level vulnerabilities
  { patterns: ['api key exposure', 'insecure endpoint', 'rate limiting', 'broken access control'], area: 'API' },
  // Database — data-layer vulnerabilities
  { patterns: ['sql injection', 'sqli', 'sql_injection', 'nosql injection', 'hardcoded_sql', 'sql_expression', 'sql expression', 'raw sql', 'raw_sql', 'orm injection'], area: 'Database' },
  // Authentication — identity verification vulnerabilities
  { patterns: ['authentication bypass', 'auth bypass', 'brute force', 'session fixation', 'session hijacking', 'broken authentication', 'default credentials', 'missing authentication'], area: 'Authentication' },
  // Authorization — access control vulnerabilities
  { patterns: ['authorization bypass', 'privilege escalation', 'idor', 'insecure direct object reference', 'broken access control', 'missing authorization'], area: 'Authorization' },
  // Configuration — misconfiguration vulnerabilities
  { patterns: ['misconfiguration', 'insecure default', 'debug mode', 'verbose error', 'insecure configuration'], area: 'Configuration' },
  // Dependencies — supply chain vulnerabilities
  { patterns: ['vulnerable dependency', 'outdated dependency', 'known vulnerability', 'supply chain'], area: 'Dependencies' },
  // Cryptography — cryptographic weaknesses
  { patterns: ['weak cipher', 'insecure hash', 'md5', 'sha1', 'broken crypto', 'cryptography', 'weak-cryptography', 'weak_cryptography', 'weak cryptography', 'weak hashing', 'hashlib', 'insecure encryption', 'deprecated algorithm'], area: 'Cryptography' },
  // Secrets — exposed secrets and credentials
  { patterns: ['hardcoded secret', 'leaked credential', 'exposed secret', 'hardcoded password', 'hardcoded api key', 'private key exposure', 'secret in source'], area: 'Secrets' },
  // File System — file access vulnerabilities
  { patterns: ['path traversal', 'file inclusion', 'directory traversal', 'lfi', 'rfi', 'unrestricted upload', 'arbitrary file'], area: 'File System' },
  // Network — network-level vulnerabilities
  { patterns: ['ssrf', 'server-side request forgery', 'dns rebinding', 'open port'], area: 'Network' },
  // Infrastructure — deployment vulnerabilities
  { patterns: ['container escape', 'docker vulnerability', 'kubernetes misconfiguration', 'iam misconfiguration', 'terraform misconfiguration'], area: 'Infrastructure' },
]

/* ------------------------------------------------------------------ */
/*  Word-boundary–aware matching                                       */
/* ------------------------------------------------------------------ */

/**
 * Check whether `text` contains `pattern` as a recognizable token.
 * Handles underscore-separated, hyphen-separated, and space-separated words.
 *
 * Examples:
 *   wordMatch('hardcoded_sql_expressions', 'sql') → false  (substring only)
 *   wordMatch('hardcoded_sql_expressions', 'hardcoded_sql') → true
 *   wordMatch('weak-cryptography', 'cryptography') → true
 *   wordMatch('md5 hash usage', 'md5') → true
 */
function tokenMatch(text: string, pattern: string): boolean {
  // Normalize both to a common token format: replace separators with spaces
  const normalizedText = text.replace(/[_\-/.]/g, ' ').replace(/\s+/g, ' ')
  const normalizedPattern = pattern.replace(/[_\-/.]/g, ' ').replace(/\s+/g, ' ')

  // Check for exact containment as a token sequence
  if (normalizedText === normalizedPattern) return true
  if (normalizedText.startsWith(normalizedPattern + ' ')) return true
  if (normalizedText.endsWith(' ' + normalizedPattern)) return true
  if (normalizedText.includes(' ' + normalizedPattern + ' ')) return true

  // Also check the original text for patterns that are themselves multi-word
  // or for very specific identifiers (e.g., 'md5', 'sha1', 'xss')
  if (pattern.length <= 4) {
    // Short patterns: require word boundary in original text
    const re = new RegExp(`(?:^|[^a-z0-9])${escapeRegex(pattern)}(?:$|[^a-z0-9])`)
    return re.test(text)
  }

  // For longer patterns, check normalized containment
  return normalizedText.includes(normalizedPattern)
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/* ------------------------------------------------------------------ */
/*  Adjacency map for edge generation                                  */
/* ------------------------------------------------------------------ */

/** Pairs of areas that share a logical architectural relationship. */
const ADJACENCY_PAIRS: [SecurityArea, SecurityArea][] = [
  ['Frontend', 'API'],
  ['Frontend', 'Authentication'],
  ['API', 'Backend'],
  ['API', 'Authentication'],
  ['API', 'Authorization'],
  ['Backend', 'Database'],
  ['Backend', 'File System'],
  ['Backend', 'Network'],
  ['Backend', 'Authentication'],
  ['Backend', 'Authorization'],
  ['Backend', 'Cryptography'],
  ['Authentication', 'Database'],
  ['Authentication', 'Cryptography'],
  ['Authentication', 'Secrets'],
  ['Authorization', 'Database'],
  ['Database', 'Secrets'],
  ['Database', 'Cryptography'],
  ['Configuration', 'Secrets'],
  ['Configuration', 'Infrastructure'],
  ['Dependencies', 'Backend'],
  ['Dependencies', 'Frontend'],
  ['Cryptography', 'Secrets'],
  ['Cryptography', 'Network'],
  ['Infrastructure', 'Network'],
  ['Infrastructure', 'Backend'],
  ['File System', 'Infrastructure'],
]

/* ------------------------------------------------------------------ */
/*  Severity helpers                                                   */
/* ------------------------------------------------------------------ */

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
}

export function calculateHighestSeverity(severities: string[]): SeverityLevel {
  let maxRank = -1
  let maxSev: SeverityLevel = 'LOW'
  for (const raw of severities) {
    const sev = raw.toUpperCase()
    const rank = SEVERITY_RANK[sev] ?? 0
    if (rank > maxRank) {
      maxRank = rank
      maxSev = sev as SeverityLevel
    }
  }
  return maxSev
}

/* ------------------------------------------------------------------ */
/*  Classification                                                     */
/* ------------------------------------------------------------------ */

/**
 * Classify a single finding into one or more security areas.
 *
 * Strategy:
 *   1. Match the finding's `category` against CATEGORY_RULES (highest signal).
 *   2. Match the finding's `title` against CATEGORY_RULES (secondary signal).
 *   3. Match the finding's `file_path` against PATH_RULES (structural signal).
 *   4. Fallback by file extension if nothing matched.
 *
 * Uses token-aware matching to avoid false positives from naive substrings.
 */
export function classifySecurityAreas(finding: ApiFinding): SecurityArea[] {
  const areas = new Set<SecurityArea>()
  const fileLower = (finding.file_path ?? '').toLowerCase().replace(/\\/g, '/')
  const categoryLower = (finding.category ?? '').toLowerCase()
  const titleLower = (finding.title ?? '').toLowerCase()

  // 1. Match category against CATEGORY_RULES (strongest signal)
  for (const rule of CATEGORY_RULES) {
    for (const pattern of rule.patterns) {
      if (tokenMatch(categoryLower, pattern)) {
        areas.add(rule.area)
      }
    }
  }

  // 2. Match title against CATEGORY_RULES (secondary signal)
  for (const rule of CATEGORY_RULES) {
    for (const pattern of rule.patterns) {
      if (tokenMatch(titleLower, pattern)) {
        areas.add(rule.area)
      }
    }
  }

  // 3. Match file path against PATH_RULES (structural signal)
  for (const rule of PATH_RULES) {
    for (const pattern of rule.patterns) {
      if (fileLower.includes(pattern)) {
        areas.add(rule.area)
      }
    }
  }

  // 4. Fallback: derive from file extension if nothing matched
  if (areas.size === 0) {
    if (/\.(py|rb|go|java|cs|php)$/i.test(fileLower)) {
      areas.add('Backend')
    } else if (/\.(js|jsx|ts|tsx|vue|svelte)$/i.test(fileLower)) {
      areas.add('Frontend')
    } else if (/\.(sql|db|sqlite)$/i.test(fileLower)) {
      areas.add('Database')
    } else if (/\.(ya?ml|toml|ini|cfg|conf|json)$/i.test(fileLower)) {
      areas.add('Configuration')
    } else {
      areas.add('Backend')
    }
  }

  return Array.from(areas)
}

/* ------------------------------------------------------------------ */
/*  Aggregation                                                        */
/* ------------------------------------------------------------------ */

interface AreaBucket {
  area: SecurityArea
  findingIds: string[]
  files: Set<string>
  severities: string[]
}

function aggregateAreas(findings: ApiFinding[]): Map<SecurityArea, AreaBucket> {
  const map = new Map<SecurityArea, AreaBucket>()

  for (const finding of findings) {
    const areas = classifySecurityAreas(finding)
    for (const area of areas) {
      let bucket = map.get(area)
      if (!bucket) {
        bucket = { area, findingIds: [], files: new Set(), severities: [] }
        map.set(area, bucket)
      }
      bucket.findingIds.push(finding.id)
      if (finding.file_path) bucket.files.add(finding.file_path)
      bucket.severities.push(finding.severity)
    }
  }

  return map
}

/* ------------------------------------------------------------------ */
/*  Deterministic layout                                               */
/* ------------------------------------------------------------------ */

/**
 * Position N nodes inside a 0-100 viewBox.
 * Uses an elliptical layout sorted alphabetically by area name
 * so the same set of areas always produces the same positions.
 */
function computeNodeLayout(sortedAreas: SecurityArea[]): Map<SecurityArea, { x: number; y: number }> {
  const positions = new Map<SecurityArea, { x: number; y: number }>()
  const count = sortedAreas.length

  if (count === 0) return positions

  if (count === 1) {
    positions.set(sortedAreas[0], { x: 50, y: 50 })
    return positions
  }

  if (count === 2) {
    positions.set(sortedAreas[0], { x: 30, y: 50 })
    positions.set(sortedAreas[1], { x: 70, y: 50 })
    return positions
  }

  // Elliptical distribution
  const cx = 50
  const cy = 50
  const rx = 34  // horizontal radius
  const ry = 30  // vertical radius

  for (let i = 0; i < count; i++) {
    // Start from the top (-π/2) and go clockwise
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / count
    const x = Math.round((cx + rx * Math.cos(angle)) * 10) / 10
    const y = Math.round((cy + ry * Math.sin(angle)) * 10) / 10
    positions.set(sortedAreas[i], { x, y })
  }

  return positions
}

/* ------------------------------------------------------------------ */
/*  Edge generation                                                    */
/* ------------------------------------------------------------------ */

function generateEdges(presentAreas: Set<SecurityArea>, nodeMap: Map<SecurityArea, GraphNode>): GraphEdge[] {
  const edges: GraphEdge[] = []

  for (const [a, b] of ADJACENCY_PAIRS) {
    if (presentAreas.has(a) && presentAreas.has(b)) {
      const nodeA = nodeMap.get(a)
      const nodeB = nodeMap.get(b)
      const aHigh = nodeA && (nodeA.highestSeverity === 'CRITICAL' || nodeA.highestSeverity === 'HIGH')
      const bHigh = nodeB && (nodeB.highestSeverity === 'CRITICAL' || nodeB.highestSeverity === 'HIGH')
      edges.push({
        from: a.toLowerCase().replace(/\s+/g, '-'),
        to: b.toLowerCase().replace(/\s+/g, '-'),
        active: !!(aHigh || bHigh),
      })
    }
  }

  return edges
}

/* ------------------------------------------------------------------ */
/*  Main entry point                                                   */
/* ------------------------------------------------------------------ */

/**
 * Build a complete graph from an array of findings.
 * Returns an empty graph (no nodes, no edges) when there are no findings.
 */
export function buildGraphFromFindings(findings: ApiFinding[]): GraphData {
  if (!findings || findings.length === 0) {
    return { nodes: [], edges: [] }
  }

  // 1. Aggregate findings into area buckets
  const areaBuckets = aggregateAreas(findings)

  // 2. Sort areas alphabetically for deterministic layout
  const sortedAreas = (Array.from(areaBuckets.keys()) as SecurityArea[]).sort()

  // 3. Compute positions
  const positions = computeNodeLayout(sortedAreas)

  // 4. Build nodes
  const nodeMap = new Map<SecurityArea, GraphNode>()
  const nodes: GraphNode[] = []

  for (const area of sortedAreas) {
    const bucket = areaBuckets.get(area)!
    const pos = positions.get(area)!
    const node: GraphNode = {
      id: area.toLowerCase().replace(/\s+/g, '-'),
      label: area,
      kind: AREA_KIND[area],
      x: pos.x,
      y: pos.y,
      vulnerabilityCount: bucket.findingIds.length,
      highestSeverity: calculateHighestSeverity(bucket.severities),
      vulnerabilities: bucket.findingIds,
      files: Array.from(bucket.files),
    }
    nodeMap.set(area, node)
    nodes.push(node)
  }

  // 5. Build edges
  const presentAreas = new Set(sortedAreas)
  const edges = generateEdges(presentAreas, nodeMap)

  return { nodes, edges }
}
