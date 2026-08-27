'use client'

import { cn } from '@/lib/utils'
import type { Severity } from '@/lib/threat-data'

const styles: Record<Severity, string> = {
  critical: 'bg-critical/15 text-critical border-critical/40',
  high: 'bg-high/15 text-high border-high/40',
  medium: 'bg-medium/15 text-medium border-medium/40',
  low: 'bg-low/15 text-low border-low/40',
}

const dot: Record<Severity, string> = {
  critical: 'bg-critical',
  high: 'bg-high',
  medium: 'bg-medium',
  low: 'bg-low',
}

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity
  className?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider',
        styles[severity],
        className,
      )}
    >
      <span
        className={cn(
          'size-1.5 rounded-full',
          dot[severity],
          severity === 'critical' && 'animate-pulse',
        )}
        aria-hidden
      />
      {severity}
    </span>
  )
}
