'use client'

import { useState } from 'react'
import { analyzeSource } from '@/lib/api'

type ScanStage =
  | 'idle'
  | 'analyzing'
  | 'building-graph'
  | 'complete'
  | 'error'

const STAGE_LABELS: Record<ScanStage, string> = {
  idle: '',
  analyzing: 'Analyzing source code...',
  'building-graph': 'Building security graph...',
  complete: 'Analysis complete',
  error: 'Scan failed',
}

const STAGE_ORDER: ScanStage[] = ['analyzing', 'building-graph', 'complete']

interface SourceUploadProps {
  projectName: string
  onScanComplete: (report: unknown) => void
}

export function SourceUpload({ projectName, onScanComplete }: SourceUploadProps) {
  const [filename, setFilename] = useState('source.py')
  const [sourceCode, setSourceCode] = useState('')
  const [sourceFiles, setSourceFiles] = useState<Array<{ filename: string; source_code: string }>>([])
  const [stage, setStage] = useState<ScanStage>('idle')
  const [error, setError] = useState('')

  const handleAnalyze = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (!sourceCode.trim() && sourceFiles.length === 0) return
    if (!projectName.trim()) {
      setError('Enter a project name.')
      return
    }

    if (sourceCode.trim() && !filename.trim()) {
      setError('Enter a filename for the pasted source code.')
      return
    }

    setError('')
    setStage('analyzing')

    try {
      const stageTimer = (nextStage: ScanStage, delayMs: number) =>
        new Promise<void>((resolve) => setTimeout(() => { setStage(nextStage); resolve() }, delayMs))

      const files = sourceCode.trim()
        ? [...sourceFiles, { filename, source_code: sourceCode }]
        : sourceFiles

      const scanPromise = analyzeSource(projectName.trim(), files)
      
      await stageTimer('building-graph', 800)
      
      const report = await scanPromise

      await stageTimer('complete', 400)
      onScanComplete(report)

      setTimeout(() => {
        setSourceCode('')
        setSourceFiles([])
        setStage('idle')
      }, 1500)
    } catch (err) {
      setStage('error')
      setError(err instanceof Error ? err.message : 'The scan failed. Please try again.')
    }
  }

  const handleFiles = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files ?? []).filter((file) =>
      /\.(py|js|jsx|ts|tsx)$/i.test(file.name),
    )
    Promise.all(selectedFiles.map(async (file) => ({
      filename: file.webkitRelativePath || file.name,
      source_code: await file.text(),
    }))).then((newFiles) => setSourceFiles((existingFiles) => [...existingFiles, ...newFiles]))
  }

  const isScanning = stage !== 'idle' && stage !== 'complete' && stage !== 'error'
  const stageIndex = STAGE_ORDER.indexOf(stage)

  return (
    <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
      <form className="flex flex-col gap-4" onSubmit={handleAnalyze}>
        {sourceFiles.length > 0 && (
          <div className="flex items-center gap-2 text-sm font-mono text-muted-foreground border border-border bg-muted/20 px-3 py-2 rounded-md">
            <span>{sourceFiles.length} additional file{sourceFiles.length === 1 ? '' : 's'} added.</span>
            <button type="button" onClick={() => setSourceFiles([])} className="ml-auto underline hover:text-foreground">Clear</button>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="md:col-span-1">
            <label htmlFor="pasted-filename" className="block font-mono text-xs font-medium text-muted-foreground mb-1.5">
              Source File
            </label>
            <input
              type="text"
              id="pasted-filename"
              value={filename}
              disabled={isScanning}
              className="block w-full border border-border px-3 py-2 rounded-md text-sm bg-background font-mono text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
              onChange={(e) => setFilename(e.target.value)}
            />
          </div>
          <div className="md:col-span-3">
             <label htmlFor="source-code" className="block font-mono text-xs font-medium text-muted-foreground mb-1.5 flex justify-between">
              <span>Source Code</span>
              <span className="relative">
                <input
                  type="file"
                  multiple
                  accept=".py,.js,.jsx,.ts,.tsx"
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  title="Add files"
                  onChange={handleFiles}
                />
                <span className="text-primary hover:underline cursor-pointer">or upload files</span>
              </span>
            </label>
            <textarea
              id="source-code"
              value={sourceCode}
              rows={8}
              disabled={isScanning}
              spellCheck={false}
              className="block w-full resize-y border border-border bg-[#0d1117] rounded-md px-4 py-3 font-mono text-sm text-[#c9d1d9] focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
              placeholder="Paste your source code here..."
              onChange={(e) => setSourceCode(e.target.value)}
            />
          </div>
        </div>

        <div className="flex justify-end mt-2">
          <button type="submit" disabled={isScanning || (!sourceCode.trim() && sourceFiles.length === 0) || !projectName.trim()} className="rounded-md bg-primary px-6 py-2 font-mono text-sm font-semibold text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50 transition-colors">
            {isScanning ? 'Scanning...' : 'Analyze Source'}
          </button>
        </div>
      </form>

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
        </div>
      )}

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
