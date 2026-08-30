'use client'

import { useState } from 'react'
import { ZipUpload } from './zip-upload'
import { FolderUpload } from './folder-upload'
import { SourceUpload } from './source-upload'
import type { ReportDetail } from '@/lib/threat-data'

type InputMode = 'zip' | 'folder' | 'source'

interface ProjectInputProps {
  onScanComplete: (report: unknown) => void
}

export function ProjectInput({ onScanComplete }: ProjectInputProps) {
  const [mode, setMode] = useState<InputMode>('zip')
  const [projectName, setProjectName] = useState('')

  const handleAutoName = (name: string) => {
    if (!projectName) {
      setProjectName(name)
    }
  }

  return (
    <div className="rounded-md border border-border bg-card p-6">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-foreground">Analyze Your Project</h2>
        <p className="mt-1 font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
          Provide your source code for security analysis.
        </p>
      </div>

      <div className="mb-6 flex flex-col md:flex-row md:items-end gap-6">
        <div className="flex-1 max-w-md">
          <label htmlFor="unified-project-name" className="block font-mono text-xs font-medium text-muted-foreground mb-1.5">
            Project Name
          </label>
          <input
            type="text"
            id="unified-project-name"
            value={projectName}
            onChange={(e) => setProjectName(e.target.value)}
            placeholder="my-project"
            className="block w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground/50 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
      </div>

      <div className="mb-6 flex gap-2 overflow-x-auto pb-2 sm:pb-0">
        <button
          onClick={() => setMode('zip')}
          className={`flex items-center gap-2 rounded-md px-4 py-2 font-mono text-xs font-semibold transition-colors shrink-0 ${
            mode === 'zip'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted/20 text-muted-foreground hover:bg-muted/40'
          }`}
        >
          <span>📦</span> ZIP File
        </button>
        <button
          onClick={() => setMode('folder')}
          className={`flex items-center gap-2 rounded-md px-4 py-2 font-mono text-xs font-semibold transition-colors shrink-0 ${
            mode === 'folder'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted/20 text-muted-foreground hover:bg-muted/40'
          }`}
        >
          <span>📁</span> Folder
        </button>
        <button
          onClick={() => setMode('source')}
          className={`flex items-center gap-2 rounded-md px-4 py-2 font-mono text-xs font-semibold transition-colors shrink-0 ${
            mode === 'source'
              ? 'bg-primary text-primary-foreground'
              : 'bg-muted/20 text-muted-foreground hover:bg-muted/40'
          }`}
        >
          <span>&lt;/&gt;</span> Source Code
        </button>
      </div>

      <div className="mt-4 border-t border-border/50 pt-6 min-h-[250px]">
        {mode === 'zip' && (
          <ZipUpload
            projectName={projectName}
            onAutoName={handleAutoName}
            onScanComplete={onScanComplete}
          />
        )}
        {mode === 'folder' && (
          <FolderUpload
            projectName={projectName}
            onAutoName={handleAutoName}
            onScanComplete={onScanComplete}
          />
        )}
        {mode === 'source' && (
          <SourceUpload
            projectName={projectName}
            onScanComplete={onScanComplete}
          />
        )}
      </div>
    </div>
  )
}
