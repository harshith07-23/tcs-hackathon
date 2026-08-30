'use client'

import { useState, useRef, useCallback } from 'react'

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type ScanStage =
  | 'idle'
  | 'uploading'
  | 'extracting'
  | 'analyzing'
  | 'building-graph'
  | 'complete'
  | 'error'

const STAGE_LABELS: Record<ScanStage, string> = {
  idle: '',
  uploading: 'Uploading ZIP archive…',
  extracting: 'Extracting project files…',
  analyzing: 'Analyzing source code…',
  'building-graph': 'Building security graph…',
  complete: 'Analysis complete',
  error: 'Scan failed',
}

const STAGE_ORDER: ScanStage[] = ['uploading', 'extracting', 'analyzing', 'building-graph', 'complete']

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${sizes[i]}`
}

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

interface ZipUploadProps {
  projectName: string
  onAutoName?: (name: string) => void
  onScanComplete: (report: unknown) => void
}

export function ZipUpload({ projectName, onAutoName, onScanComplete }: ZipUploadProps) {
  const [file, setFile] = useState<File | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [stage, setStage] = useState<ScanStage>('idle')
  const [error, setError] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const MAX_SIZE = 50 * 1024 * 1024 // 50 MB

  const handleFileSelect = useCallback((selectedFile: File | null) => {
    setError('')
    if (!selectedFile) return

    if (!selectedFile.name.toLowerCase().endsWith('.zip')) {
      setError('Please select a ZIP file.')
      return
    }
    if (selectedFile.size > MAX_SIZE) {
      setError(`File exceeds the maximum allowed size of ${MAX_SIZE / (1024 * 1024)} MB.`)
      return
    }
    if (selectedFile.size === 0) {
      setError('The selected file is empty.')
      return
    }
    setFile(selectedFile)
    // Auto-fill project name from filename
    if (!projectName && onAutoName) {
      onAutoName(selectedFile.name.replace(/\.zip$/i, ''))
    }
  }, [projectName, onAutoName, MAX_SIZE])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const droppedFile = e.dataTransfer.files[0]
    handleFileSelect(droppedFile ?? null)
  }, [handleFileSelect])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
  }, [])

  const clearFile = () => {
    setFile(null)
    setError('')
    setStage('idle')
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleAnalyze = async () => {
    if (!file) {
      setError('Select a ZIP file first.')
      return
    }
    if (!projectName.trim()) {
      setError('Enter a project name.')
      return
    }

    setError('')
    setStage('uploading')

    try {
      // Simulate stage progression since upload is a single POST
      const stageTimer = (nextStage: ScanStage, delayMs: number) =>
        new Promise<void>((resolve) => setTimeout(() => { setStage(nextStage); resolve() }, delayMs))

      const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'
      const formData = new FormData()
      formData.append('project_name', projectName.trim())
      formData.append('file', file)

      // Fire the request
      const fetchPromise = fetch(`${apiUrl}/api/scan`, { method: 'POST', body: formData })

      // While waiting, advance stages for UX feedback
      await stageTimer('extracting', 800)
      await stageTimer('analyzing', 1200)

      const response = await fetchPromise

      if (!response.ok) {
        const body = await response.json().catch(() => null)
        throw new Error(body?.detail ?? `Server returned ${response.status}`)
      }

      setStage('building-graph')
      const report = await response.json()

      await stageTimer('complete', 400)

      onScanComplete(report)

      // Reset form after success
      setTimeout(() => {
        setFile(null)
        setStage('idle')
        if (fileInputRef.current) fileInputRef.current.value = ''
      }, 1500)
    } catch (err) {
      setStage('error')
      setError(err instanceof Error ? err.message : 'The scan failed. Please try again.')
    }
  }

  const isScanning = stage !== 'idle' && stage !== 'complete' && stage !== 'error'
  const stageIndex = STAGE_ORDER.indexOf(stage)

  return (
    <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
      {/* Drop zone or selected file */}
      {!file ? (
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => fileInputRef.current?.click()}
          className={`
            group relative flex cursor-pointer flex-col items-center justify-center rounded-md border-2 border-dashed
            px-6 py-10 transition-colors duration-200
            ${dragOver
              ? 'border-primary bg-primary/5'
              : 'border-border hover:border-muted-foreground/60 hover:bg-muted/20'
            }
          `}
        >
          {/* ZIP icon */}
          <svg
            width="40" height="40" viewBox="0 0 24 24" fill="none"
            stroke={dragOver ? 'var(--primary)' : 'var(--muted-foreground)'}
            strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"
            className="mb-3 opacity-60 transition-all group-hover:opacity-80"
          >
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="12" y1="12" x2="12" y2="18" />
            <polyline points="9 15 12 18 15 15" />
          </svg>

          <p className="font-mono text-sm font-medium text-foreground">
            {dragOver ? 'Drop your ZIP here' : 'Drop your project ZIP here'}
          </p>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            or <span className="text-primary underline underline-offset-2">browse files</span>
          </p>
          <p className="mt-3 font-mono text-[10px] text-muted-foreground/60 uppercase tracking-wider">
            ZIP files up to {MAX_SIZE / (1024 * 1024)} MB
          </p>

          <input
            ref={fileInputRef}
            type="file"
            accept=".zip"
            className="hidden"
            onChange={(e) => handleFileSelect(e.target.files?.[0] ?? null)}
          />
        </div>
      ) : (
        <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-4 py-3">
          <div className="flex items-center gap-3 min-w-0">
            {/* File icon */}
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-border bg-muted/30">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
              </svg>
            </div>
            <div className="min-w-0">
              <p className="truncate font-mono text-sm font-semibold text-foreground">{file.name}</p>
              <p className="font-mono text-xs text-muted-foreground">{formatBytes(file.size)}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 ml-4">
            {!isScanning && (
              <button
                type="button"
                onClick={clearFile}
                className="rounded-md border border-border px-3 py-1.5 font-mono text-xs text-muted-foreground hover:bg-muted/30 hover:text-foreground transition-colors"
              >
                Change
              </button>
            )}
            <button
              type="button"
              onClick={handleAnalyze}
              disabled={isScanning || !projectName.trim()}
              className="rounded-md bg-primary px-4 py-1.5 font-mono text-xs font-semibold text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50 transition-colors"
            >
              {isScanning ? 'Scanning…' : 'Analyze Project'}
            </button>
          </div>
        </div>
      )}

      {/* Stage progress */}
      {isScanning && (
        <div className="mt-4 rounded-md border border-border bg-muted/10 px-4 py-3">
          <div className="flex items-center gap-2 mb-3">
            <div className="size-2 rounded-full bg-primary animate-pulse" />
            <span className="font-mono text-xs font-semibold text-foreground">
              {STAGE_LABELS[stage]}
            </span>
          </div>
          <div className="flex gap-1">
            {STAGE_ORDER.map((s, i) => (
              <div
                key={s}
                className="h-1 flex-1 rounded-full transition-colors duration-300"
                style={{
                  backgroundColor: i <= stageIndex
                    ? 'var(--primary)'
                    : 'var(--muted)',
                }}
              />
            ))}
          </div>
          <div className="mt-2 flex justify-between font-mono text-[9px] uppercase tracking-wider text-muted-foreground/70">
            <span>Upload</span>
            <span>Extract</span>
            <span>Analyze</span>
            <span>Graph</span>
            <span>Done</span>
          </div>
        </div>
      )}

      {/* Success state */}
      {stage === 'complete' && (
        <div className="mt-4 flex items-center gap-2 rounded-md border border-primary/30 bg-primary/5 px-4 py-3">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12" />
          </svg>
          <span className="font-mono text-xs font-semibold text-primary">
            Analysis complete — results updated below
          </span>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="mt-4 flex items-start gap-2 rounded-md border border-critical/30 bg-critical/5 px-4 py-3">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--critical)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="shrink-0 mt-0.5">
            <circle cx="12" cy="12" r="10" />
            <line x1="15" y1="9" x2="9" y2="15" />
            <line x1="9" y1="9" x2="15" y2="15" />
          </svg>
          <span className="font-mono text-xs text-critical">{error}</span>
        </div>
      )}
    </div>
  )
}
