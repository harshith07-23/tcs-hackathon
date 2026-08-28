'use client'

import { useState } from 'react'
import { buildGraphFromFindings, type GraphNode, type GraphEdge, type SeverityLevel } from '@/lib/graph-builder'
import type { ApiFinding } from '@/lib/threat-data'

/* ------------------------------------------------------------------ */
/*  Severity → CSS variable mapping                                    */
/* ------------------------------------------------------------------ */

const severityColor: Record<SeverityLevel, string> = {
  CRITICAL: 'var(--critical)',
  HIGH: 'var(--high)',
  MEDIUM: 'var(--medium)',
  LOW: 'var(--low)',
  INFO: 'var(--low)',
}

const severityLabel: Record<SeverityLevel, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

interface ArchitectureGraphProps {
  findings: ApiFinding[]
  /** Optional: currently-selected finding ID for highlight */
  selectedFindingId?: string | null
  /** Optional: callback when a node is clicked */
  onNodeClick?: (node: GraphNode) => void
}

export function ArchitectureGraph({ findings, selectedFindingId, onNodeClick }: ArchitectureGraphProps) {
  const [hovered, setHovered] = useState<string | null>(null)

  // Build graph from actual vulnerability data — fully reactive to prop changes
  const { nodes, edges } = buildGraphFromFindings(findings)

  // Index nodes by id for edge lookups
  const nodeById = Object.fromEntries(nodes.map((n) => [n.id, n]))

  // Determine if a node contains the selected finding
  const isNodeSelected = (node: GraphNode) =>
    selectedFindingId != null && node.vulnerabilities.includes(selectedFindingId)

  /* ---- Empty state ---- */
  if (nodes.length === 0) {
    return (
      <div className="relative flex w-full flex-col items-center justify-center rounded-md border border-border bg-[repeating-linear-gradient(0deg,transparent,transparent_23px,color-mix(in_oklab,var(--border)_50%,transparent)_24px),repeating-linear-gradient(90deg,transparent,transparent_23px,color-mix(in_oklab,var(--border)_50%,transparent)_24px)] py-20">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--muted-foreground)" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" className="mb-4 opacity-40">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <polyline points="9 12 11 14 15 10" />
        </svg>
        <p className="font-mono text-sm font-semibold text-muted-foreground">
          No affected security areas detected
        </p>
        <p className="mt-1 font-mono text-[11px] text-muted-foreground/60">
          The analyzed project currently has no detected vulnerabilities.
        </p>
      </div>
    )
  }

  /* ---- Graph ---- */
  return (
    <div className="relative w-full overflow-hidden rounded-md border border-border bg-[repeating-linear-gradient(0deg,transparent,transparent_23px,color-mix(in_oklab,var(--border)_50%,transparent)_24px),repeating-linear-gradient(90deg,transparent,transparent_23px,color-mix(in_oklab,var(--border)_50%,transparent)_24px)]">
      <svg viewBox="0 0 100 100" className="h-[340px] w-full" preserveAspectRatio="xMidYMid meet">
        {/* edges */}
        {edges.map((e: GraphEdge) => {
          const a = nodeById[e.from]
          const b = nodeById[e.to]
          if (!a || !b) return null
          const connected = hovered === e.from || hovered === e.to
          return (
            <g key={`${e.from}-${e.to}`}>
              <line
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={
                  e.active
                    ? 'var(--critical)'
                    : connected
                      ? 'var(--primary)'
                      : 'color-mix(in oklab, var(--muted-foreground) 45%, transparent)'
                }
                strokeWidth={e.active ? 0.7 : 0.4}
              />
              {e.active && (
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke="var(--critical)"
                  strokeWidth={0.9}
                  strokeLinecap="round"
                  strokeDasharray="1.5 4"
                  style={{ animation: 'dash-flow 1s linear infinite' }}
                />
              )}
            </g>
          )
        })}

        {/* nodes */}
        {nodes.map((n: GraphNode) => {
          const color = severityColor[n.highestSeverity]
          const active = hovered === n.id
          const selected = isNodeSelected(n)
          const isCriticalOrHigh = n.highestSeverity === 'CRITICAL' || n.highestSeverity === 'HIGH'
          return (
            <g
              key={n.id}
              onMouseEnter={() => setHovered(n.id)}
              onMouseLeave={() => setHovered(null)}
              onClick={() => onNodeClick?.(n)}
              className="cursor-pointer"
            >
              {/* Pulse ring for critical/high nodes */}
              {isCriticalOrHigh && (
                <circle
                  cx={n.x}
                  cy={n.y}
                  r={5}
                  fill="none"
                  stroke={color}
                  strokeWidth={0.5}
                  style={{ animation: 'pulse-node 1.6s ease-in-out infinite' }}
                />
              )}

              {/* Selection ring */}
              {selected && (
                <circle
                  cx={n.x}
                  cy={n.y}
                  r={4.5}
                  fill="none"
                  stroke="var(--primary)"
                  strokeWidth={0.8}
                  strokeDasharray="1.5 1"
                />
              )}

              {/* Main circle */}
              <circle
                cx={n.x}
                cy={n.y}
                r={active ? 3 : 2.3}
                fill="var(--card)"
                stroke={color}
                strokeWidth={active ? 1 : 0.7}
                style={{ filter: `drop-shadow(0 0 2px ${color})`, transition: 'r 0.15s ease' }}
              />

              {/* Inner dot */}
              <circle cx={n.x} cy={n.y} r={0.9} fill={color} />

              {/* Label */}
              <text
                x={n.x}
                y={n.y - 4.8}
                textAnchor="middle"
                className="fill-foreground font-mono"
                style={{ fontSize: '2.4px', fontWeight: 600 }}
              >
                {n.label}
              </text>

              {/* Vulnerability count badge */}
              <text
                x={n.x}
                y={n.y + 5.6}
                textAnchor="middle"
                style={{ fontSize: '1.9px', fontWeight: 700, fill: color }}
              >
                {n.vulnerabilityCount}
              </text>

              {/* Kind label */}
              <text
                x={n.x}
                y={n.y + 8}
                textAnchor="middle"
                className="fill-muted-foreground font-mono uppercase"
                style={{ fontSize: '1.6px', letterSpacing: '0.1px' }}
              >
                {n.kind}
              </text>
            </g>
          )
        })}
      </svg>

      {/* legend */}
      <div className="absolute bottom-3 left-3 flex flex-wrap items-center gap-3 rounded-sm border border-border bg-card/80 px-3 py-1.5 backdrop-blur">
        {(
          [
            ['CRITICAL', 'Critical'],
            ['HIGH', 'High'],
            ['MEDIUM', 'Medium'],
            ['LOW', 'Low'],
          ] as [SeverityLevel, string][]
        ).map(([sev, label]) => (
          <span key={sev} className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            <span className="size-2 rounded-full" style={{ backgroundColor: severityColor[sev] }} />
            {label}
          </span>
        ))}
      </div>

      {/* node count indicator */}
      <div className="absolute bottom-3 right-3 rounded-sm border border-border bg-card/80 px-2.5 py-1 backdrop-blur">
        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          {nodes.length} area{nodes.length !== 1 ? 's' : ''} · {findings.length} finding{findings.length !== 1 ? 's' : ''}
        </span>
      </div>
    </div>
  )
}
