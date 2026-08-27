'use client'

import { useEffect, useState } from 'react'

function riskBand(score: number) {
  if (score >= 75) return { label: 'Critical Exposure', color: 'var(--critical)' }
  if (score >= 50) return { label: 'Elevated Risk', color: 'var(--high)' }
  if (score >= 25) return { label: 'Moderate Risk', color: 'var(--medium)' }
  return { label: 'Low Risk', color: 'var(--low)' }
}

export function RiskGauge({ score }: { score: number }) {
  const [display, setDisplay] = useState(0)
  const band = riskBand(score)

  // Geometry for a 270° arc gauge.
  const size = 240
  const stroke = 16
  const r = (size - stroke) / 2
  const cx = size / 2
  const cy = size / 2
  const arc = 270
  const circumference = 2 * Math.PI * r
  const arcLength = (arc / 360) * circumference

  useEffect(() => {
    const start = performance.now()
    const duration = 1100
    let raf = 0
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplay(Math.round(eased * score))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [score])

  const progress = (display / 100) * arcLength

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          className="-rotate-[135deg]"
          role="img"
          aria-label={`Risk score ${score} out of 100, ${band.label}`}
        >
          {/* track */}
          <circle
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke="var(--muted)"
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${arcLength} ${circumference}`}
          />
          {/* progress */}
          <circle
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke={band.color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference}`}
            style={{
              filter: `drop-shadow(0 0 6px ${band.color})`,
              transition: 'stroke 0.4s ease',
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-6xl font-bold tabular-nums text-foreground">
            {display}
          </span>
          <span className="mt-1 font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
            Risk Index
          </span>
        </div>
      </div>
      <div
        className="mt-2 rounded-sm border px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider"
        style={{
          color: band.color,
          borderColor: `color-mix(in oklab, ${band.color} 40%, transparent)`,
          backgroundColor: `color-mix(in oklab, ${band.color} 12%, transparent)`,
        }}
      >
        {band.label}
      </div>
    </div>
  )
}
