'use client'

import { ShieldHalf, Radio } from 'lucide-react'

export function DashboardHeader() {
  return (
    <header className="flex flex-col gap-4 border-b border-border pb-5 sm:flex-row sm:items-center sm:justify-between">
      <div className="flex items-center gap-3">
        <div className="flex size-10 items-center justify-center rounded-md border border-primary/40 bg-primary/10">
          <ShieldHalf className="size-5 text-primary" />
        </div>
        <div>
          <h1 className="text-lg font-semibold tracking-tight text-foreground">Sentinel</h1>
          <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
            Threat Operations Center
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 rounded-sm border border-low/40 bg-low/10 px-3 py-1.5">
          <Radio className="size-3.5 text-low" />
          <span className="font-mono text-[11px] font-medium uppercase tracking-wider text-low">
            Live · Feed Active
          </span>
        </div>
        <div className="hidden text-right sm:block">
          <p className="font-mono text-xs text-foreground">SOC-EU-WEST-1</p>
          <p className="font-mono text-[10px] text-muted-foreground">Sync 00:00:03 UTC</p>
        </div>
      </div>
    </header>
  )
}
