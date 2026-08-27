'use client'

import { ArrowUpRight, ArrowDownRight } from 'lucide-react'
import type { Metric } from '@/lib/threat-data'

export function MetricStrip({ metrics }: { metrics: Metric[] }) {
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {metrics.map((m: Metric) => {
        const Icon = m.trend === 'up' ? ArrowUpRight : ArrowDownRight
        return (
          <div key={m.label} className="rounded-md border border-border bg-card p-4">
            <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              {m.label}
            </p>
            <div className="mt-2 flex items-baseline justify-between">
              <span className="font-mono text-2xl font-bold tabular-nums text-foreground">
                {m.value}
              </span>
              <span className="flex items-center gap-0.5 font-mono text-xs text-muted-foreground">
                <Icon className="size-3.5" />
                {m.delta}
              </span>
            </div>
          </div>
        )
      })}
    </div>
  )
}
