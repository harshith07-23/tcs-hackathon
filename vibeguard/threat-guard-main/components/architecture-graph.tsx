'use client'

import { useState } from 'react'
import { archNodes, archEdges, type NodeStatus } from '@/lib/threat-data'

const statusColor: Record<NodeStatus, string> = {
  secure: 'var(--low)',
  monitored: 'var(--medium)',
  compromised: 'var(--critical)',
}

export function ArchitectureGraph({ riskScore }: { riskScore: number }) {
  const [hovered, setHovered] = useState<string | null>(null)
  const nodeById = Object.fromEntries(archNodes.map((n) => [n.id, n]))
  const dynamicNodes = archNodes.map((node, index) => ({
    ...node,
    status: riskScore >= 75 && index % 3 === 0
      ? 'compromised' as NodeStatus
      : riskScore >= 35 && index % 2 === 0
        ? 'monitored' as NodeStatus
        : 'secure' as NodeStatus,
  }))

  return (
    <div className="relative w-full overflow-hidden rounded-md border border-border bg-[repeating-linear-gradient(0deg,transparent,transparent_23px,color-mix(in_oklab,var(--border)_50%,transparent)_24px),repeating-linear-gradient(90deg,transparent,transparent_23px,color-mix(in_oklab,var(--border)_50%,transparent)_24px)]">
      <svg viewBox="0 0 100 100" className="h-[340px] w-full" preserveAspectRatio="xMidYMid meet">
        {/* edges */}
        {archEdges.map((e) => {
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
        {dynamicNodes.map((n) => {
          const color = statusColor[n.status]
          const active = hovered === n.id
          return (
            <g
              key={n.id}
              onMouseEnter={() => setHovered(n.id)}
              onMouseLeave={() => setHovered(null)}
              className="cursor-pointer"
            >
              {n.status === 'compromised' && (
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
              <circle
                cx={n.x}
                cy={n.y}
                r={active ? 3 : 2.3}
                fill="var(--card)"
                stroke={color}
                strokeWidth={active ? 1 : 0.7}
                style={{ filter: `drop-shadow(0 0 2px ${color})`, transition: 'r 0.15s ease' }}
              />
              <circle cx={n.x} cy={n.y} r={0.9} fill={color} />
              <text
                x={n.x}
                y={n.y - 4.2}
                textAnchor="middle"
                className="fill-foreground font-mono"
                style={{ fontSize: '2.4px', fontWeight: 600 }}
              >
                {n.label}
              </text>
              <text
                x={n.x}
                y={n.y + 6.4}
                textAnchor="middle"
                className="fill-muted-foreground font-mono uppercase"
                style={{ fontSize: '1.8px', letterSpacing: '0.1px' }}
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
            ['secure', 'Secure'],
            ['monitored', 'Monitored'],
            ['compromised', 'Compromised'],
          ] as [NodeStatus, string][]
        ).map(([status, label]) => (
          <span key={status} className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            <span className="size-2 rounded-full" style={{ backgroundColor: statusColor[status] }} />
            {label}
          </span>
        ))}
      </div>
    </div>
  )
}
