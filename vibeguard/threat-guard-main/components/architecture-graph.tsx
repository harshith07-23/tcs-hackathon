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
  const [tooltip, setTooltip] = useState<{ node: GraphNode, x: number, y: number } | null>(null)
  const [selectedFileNode, setSelectedFileNode] = useState<GraphNode | null>(null)

  // Build graph from actual vulnerability data — fully reactive to prop changes
  const { nodes, edges } = buildGraphFromFindings(findings)

  // Index nodes by id for edge lookups
  const nodeById = Object.fromEntries(nodes.map((n) => [n.id, n]))

  // Determine if a node contains the selected finding or is the selected file
  const isNodeSelected = (node: GraphNode) =>
    (selectedFindingId != null && node.vulnerabilities.includes(selectedFindingId)) ||
    (selectedFileNode?.id === node.id)

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
      <svg 
        viewBox="0 0 100 100" 
        className="h-[440px] w-full" 
        preserveAspectRatio="xMidYMid meet"
        onClick={() => setSelectedFileNode(null)} // Click outside deselects
      >
        {/* edges */}
        {edges.map((e: GraphEdge) => {
          const a = nodeById[e.from]
          const b = nodeById[e.to]
          if (!a || !b) return null
          
          // Hover logic
          const hoveredConnected = hovered === e.from || hovered === e.to || 
                           (a.type === 'area' && hovered === a.id && b.parentId === a.id)
                           
          // Selection logic (keep edge visible if file is selected)
          const selectionConnected = selectedFileNode != null && (
            selectedFileNode.id === e.from || selectedFileNode.id === e.to ||
            (a.type === 'area' && selectedFileNode.parentId === a.id && b.id === selectedFileNode.id)
          )

          const activeEdge = e.active && (selectionConnected || selectedFileNode == null)
          const highlighted = hoveredConnected || selectionConnected
          const isHierarchy = e.isHierarchy

          return (
            <g key={`${e.from}-${e.to}`}>
              <line
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={
                  activeEdge && isHierarchy
                    ? 'var(--critical)'
                    : highlighted
                      ? 'var(--primary)'
                      : 'color-mix(in oklab, var(--muted-foreground) 45%, transparent)'
                }
                strokeWidth={isHierarchy ? (activeEdge ? 0.6 : 0.4) : (highlighted ? 0.3 : 0.15)}
                strokeDasharray={isHierarchy ? 'none' : '1 1'}
              />
              {activeEdge && isHierarchy && (
                <line
                  x1={a.x}
                  y1={a.y}
                  x2={b.x}
                  y2={b.y}
                  stroke="var(--critical)"
                  strokeWidth={0.8}
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
          
          // Parent area should look slightly highlighted if its child is selected
          const childSelected = selectedFileNode != null && selectedFileNode.parentId === n.id
          const highlighted = active || selected || childSelected

          const isCriticalOrHigh = n.highestSeverity === 'CRITICAL' || n.highestSeverity === 'HIGH'
          const isArea = n.type === 'area'

          // Sizing based on type
          const baseRadius = isArea ? 2.5 : 1.5
          const hoverRadius = isArea ? 3.2 : 2.0
          const innerRadius = isArea ? 1.0 : 0.6

          return (
            <g
              key={n.id}
              onMouseEnter={(e) => {
                setHovered(n.id)
                // Don't show temporary tooltip for files if a file is already pinned, to avoid visual clutter
                if (!(n.type === 'file' && selectedFileNode != null)) {
                  setTooltip({ node: n, x: e.clientX, y: e.clientY })
                }
              }}
              onMouseMove={(e) => {
                if (tooltip && tooltip.node.id === n.id) {
                  setTooltip({ node: n, x: e.clientX, y: e.clientY })
                }
              }}
              onMouseLeave={() => {
                setHovered(null)
                setTooltip(null)
              }}
              onClick={(e) => {
                e.stopPropagation() // Prevent SVG click from deselecting
                if (n.type === 'file') {
                  setSelectedFileNode(n)
                  setTooltip(null) // Hide temporary tooltip when pinning
                }
                onNodeClick?.(n)
              }}
              className={n.type === 'file' ? "cursor-pointer" : "cursor-default"}
            >
              {/* Pulse ring for critical/high nodes */}
              {isCriticalOrHigh && (
                <circle
                  cx={n.x}
                  cy={n.y}
                  r={baseRadius + 2.5}
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
                  r={baseRadius + 2.0}
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
                r={highlighted ? hoverRadius : baseRadius}
                fill="var(--card)"
                stroke={color}
                strokeWidth={highlighted ? 1 : 0.7}
                style={{ filter: `drop-shadow(0 0 2px ${color})`, transition: 'r 0.15s ease' }}
              />

              {/* Inner dot */}
              <circle cx={n.x} cy={n.y} r={innerRadius} fill={color} />

              {/* Label */}
              <text
                x={n.x}
                y={n.y - (isArea ? 4.5 : 3.0)}
                textAnchor="middle"
                className={isArea ? "fill-foreground font-mono font-bold" : "fill-muted-foreground font-mono"}
                style={{ fontSize: isArea ? '2.4px' : '1.8px' }}
              >
                {n.label}
              </text>

              {/* Vulnerability count badge (Areas only) */}
              {isArea && (
                <text
                  x={n.x}
                  y={n.y + 5.6}
                  textAnchor="middle"
                  style={{ fontSize: '1.9px', fontWeight: 700, fill: color }}
                >
                  {n.vulnerabilityCount}
                </text>
              )}

              {/* Kind label (Areas only) */}
              {isArea && (
                <text
                  x={n.x}
                  y={n.y + 8}
                  textAnchor="middle"
                  className="fill-muted-foreground font-mono uppercase"
                  style={{ fontSize: '1.6px', letterSpacing: '0.1px' }}
                >
                  {n.kind}
                </text>
              )}
            </g>
          )
        })}
      </svg>

      {/* Temporary Tooltip (HTML Overlay) */}
      {tooltip && (
        <div 
          className="fixed z-[60] flex w-64 flex-col gap-2 rounded-md border border-border bg-card/95 p-3 shadow-xl backdrop-blur-md pointer-events-none"
          style={{ 
            left: tooltip.x + 15, 
            top: tooltip.y + 15,
            // Ensure it doesn't go off screen
            transform: `translate(min(0px, calc(100vw - ${tooltip.x + 15 + 260}px)), min(0px, calc(100vh - ${tooltip.y + 15 + 200}px)))`
          }}
        >
          {tooltip.node.type === 'area' ? (
            <>
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-bold text-foreground">{tooltip.node.label}</span>
                <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] font-semibold" style={{ color: severityColor[tooltip.node.highestSeverity] }}>
                  {tooltip.node.highestSeverity}
                </span>
              </div>
              <div className="flex flex-col gap-1 font-mono text-xs text-muted-foreground">
                <span>Total Findings: <strong className="text-foreground">{tooltip.node.vulnerabilityCount}</strong></span>
                <span>Affected Files: <strong className="text-foreground">{tooltip.node.files?.length || 0}</strong></span>
              </div>
            </>
          ) : (
            <>
              <div className="flex flex-col gap-0.5 border-b border-border/50 pb-2">
                <span className="font-mono text-sm font-bold text-foreground break-all">{tooltip.node.label}</span>
                <span className="font-mono text-[10px] text-muted-foreground break-all">{tooltip.node.fullPath}</span>
                <span className="mt-1 font-mono text-[9px] text-muted-foreground/70 uppercase">Click to view details</span>
              </div>
            </>
          )}
        </div>
      )}

      {/* Persistent Selected File Details Panel */}
      {selectedFileNode && (
        <div className="absolute right-3 top-3 bottom-3 w-80 flex flex-col rounded-md border border-border bg-card/95 shadow-2xl backdrop-blur-md z-50">
          <div className="flex items-start justify-between border-b border-border/50 p-4 pb-3">
            <div className="flex flex-col gap-1 pr-4">
              <span className="font-mono text-lg font-bold text-foreground break-all leading-tight">
                {selectedFileNode.label}
              </span>
              <span className="font-mono text-xs text-muted-foreground break-all">
                {selectedFileNode.fullPath}
              </span>
            </div>
            <button 
              onClick={() => setSelectedFileNode(null)}
              className="text-muted-foreground hover:text-foreground transition-colors shrink-0"
              aria-label="Close details"
            >
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>
          
          <div className="flex items-center justify-between px-4 py-3 bg-muted/20 border-b border-border/50">
            <span className="font-mono text-xs font-semibold text-foreground">
              {selectedFileNode.vulnerabilityCount} finding{selectedFileNode.vulnerabilityCount !== 1 ? 's' : ''}
            </span>
            <span 
              className="rounded bg-muted px-2 py-1 font-mono text-xs font-bold tracking-wider" 
              style={{ color: severityColor[selectedFileNode.highestSeverity] }}
            >
              {selectedFileNode.highestSeverity}
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
            {selectedFileNode.findingsDetails?.map((f, i) => (
              <div key={i} className="flex flex-col rounded-md border border-border/60 bg-muted/10 p-3 hover:bg-muted/30 transition-colors">
                <span className="font-mono text-sm font-semibold text-foreground leading-snug mb-2">
                  {f.title}
                </span>
                <div className="flex flex-col gap-1.5 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Severity:</span>
                    <span className="font-bold" style={{ color: severityColor[f.severity] }}>
                      {f.severity}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Line:</span>
                    <span className="text-foreground font-semibold">
                      {f.line ? f.line : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* legend */}
      <div className="absolute bottom-3 left-3 flex flex-wrap items-center gap-3 rounded-sm border border-border bg-card/80 px-3 py-1.5 backdrop-blur z-40">
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
      <div className="absolute bottom-3 right-3 rounded-sm border border-border bg-card/80 px-2.5 py-1 backdrop-blur z-40">
        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          {nodes.filter(n => n.type === 'area').length} area(s) · {findings.length} finding(s)
        </span>
      </div>
    </div>
  )
}
