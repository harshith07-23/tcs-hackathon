'use client'

import { useState, useRef, useCallback } from 'react'
import { analyzeSource } from '@/lib/api'

const BLOCKED_DIR_NAMES = new Set([
  'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env', 'myenv', 'env3', 'venv3', 'virtualenv', 'ENV',
  'site-packages', 'dist', 'build', 'out', 'target', 'coverage', '.cache', '.tox',
  '.mypy_cache', '.pytest_cache', '.ruff_cache', 'vendor', '.idea', '.vscode', '.vs',
  '.next', '.nuxt', '.svelte-kit', 'bin', 'obj', '.eggs'
])

const ALLOWED_EXTENSIONS = new Set([
  '.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.java', '.kt', '.scala', '.groovy',
  '.go', '.rs', '.c', '.cpp', '.h', '.hpp', '.cs',
  '.php', '.rb', '.pl', '.sh', '.bash',
  '.html', '.htm', '.css', '.scss', '.less',
  '.json', '.yaml', '.yml', '.toml', '.xml', '.ini', '.cfg',
  '.env', '.example', '.properties', '.sql',
  '.txt', '.md', '.rst', '.dockerfile', '.lock'
])

const ALLOWED_FILENAMES = new Set([
  'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.dockerignore',
  'requirements.txt', 'pyproject.toml', 'setup.py', 'setup.cfg', 'Pipfile', 'Pipfile.lock', 'poetry.lock', 'tox.ini',
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', '.npmrc', '.nvmrc',
  'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
  'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle',
  'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock', 'nuget.config',
  '.env', '.env.example', '.env.local', '.gitignore', '.editorconfig', 'Makefile', 'Procfile',
  '.github', '.gitlab-ci.yml', 'Jenkinsfile'
])

type ScanStage =
  | 'idle'
  | 'uploading'
  | 'analyzing'
  | 'building-graph'
  | 'complete'
  | 'error'

const STAGE_LABELS: Record<ScanStage, string> = {
  idle: '',
  uploading: 'Uploading files...',
  analyzing: 'Analyzing source code...',
  'building-graph': 'Building security graph...',
  complete: 'Analysis complete',
  error: 'Scan failed',
}

const STAGE_ORDER: ScanStage[] = ['uploading', 'analyzing', 'building-graph', 'complete']

interface FolderUploadProps {
  projectName: string
  onAutoName?: (name: string) => void
  onScanComplete: (report: unknown) => void
}

export function FolderUpload({ projectName, onAutoName, onScanComplete }: FolderUploadProps) {
  const [sourceFiles, setSourceFiles] = useState<Array<{ filename: string; source_code: string }>>([])
  const [folderName, setFolderName] = useState('')
  const [stage, setStage] = useState<ScanStage>('idle')
  const [error, setError] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFolderSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    setError('')
    const files = Array.from(e.target.files ?? [])
    if (files.length === 0) return

    // Get folder name from the first file's path
    const firstPath = files[0].webkitRelativePath
    if (firstPath) {
      const folder = firstPath.split('/')[0]
      setFolderName(folder)
      if (!projectName && onAutoName) {
        onAutoName(folder)
      }
    }

    const selectedFiles = files.filter((file) => {
      const pathParts = (file.webkitRelativePath || file.name).split('/')
      if (pathParts.some(part => BLOCKED_DIR_NAMES.has(part))) {
        return false
      }
      
      const fileName = file.name
      if (ALLOWED_FILENAMES.has(fileName)) return true
      
      const dotIndex = fileName.lastIndexOf('.')
      if (dotIndex === -1) return false
      
      const ext = fileName.substring(dotIndex).toLowerCase()
      return ALLOWED_EXTENSIONS.has(ext)
    })

    if (selectedFiles.length === 0) {
      setError('No analyzable source files found in the selected folder.')
      return
    }

    try {
      const newFiles = await Promise.all(
        selectedFiles.map(async (file) => ({
          filename: file.webkitRelativePath || file.name,
          source_code: await file.text(),
        }))
      )
      setSourceFiles(newFiles)
    } catch (err) {
      setError('Failed to read files from the selected folder.')
    }
  }

  const clearFolder = () => {
    setSourceFiles([])
    setFolderName('')
    setError('')
    setStage('idle')
    if (fileInputRef.current) fileInputRef.current.value = ''
  }

  const handleAnalyze = async () => {
    if (sourceFiles.length === 0) {
      setError('Select a folder first.')
      return
    }
    if (!projectName.trim()) {
      setError('Enter a project name.')
      return
    }

    setError('')
    setStage('uploading')

    try {
      const stageTimer = (nextStage: ScanStage, delayMs: number) =>
        new Promise<void>((resolve) => setTimeout(() => { setStage(nextStage); resolve() }, delayMs))

      const scanPromise = analyzeSource(projectName.trim(), sourceFiles)
      
      await stageTimer('analyzing', 800)
      
      const report = await scanPromise

      setStage('building-graph')
      await stageTimer('complete', 400)

      onScanComplete(report)

      setTimeout(() => {
        clearFolder()
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
      {!folderName ? (
        <div
          onClick={() => fileInputRef.current?.click()}
          className="group relative flex cursor-pointer flex-col items-center justify-center rounded-md border-2 border-dashed border-border hover:border-muted-foreground/60 hover:bg-muted/20 px-6 py-10 transition-colors duration-200"
        >
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--muted-foreground)" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" className="mb-3 opacity-60 transition-all group-hover:opacity-80">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
          </svg>
          <p className="font-mono text-sm font-medium text-foreground">
            Browse for a folder
          </p>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            Select a folder to analyze its source files
          </p>
          <input
            ref={fileInputRef}
            type="file"
            // @ts-expect-error webkitdirectory is supported by most browsers
            webkitdirectory=""
            directory=""
            className="hidden"
            onChange={handleFolderSelect}
          />
        </div>
      ) : (
        <div className="flex items-center justify-between rounded-md border border-border bg-muted/20 px-4 py-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex size-9 shrink-0 items-center justify-center rounded-md border border-border bg-muted/30">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
              </svg>
            </div>
            <div className="min-w-0">
              <p className="truncate font-mono text-sm font-semibold text-foreground">{folderName}</p>
              <p className="font-mono text-xs text-muted-foreground">{sourceFiles.length} source files found</p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0 ml-4">
            {!isScanning && (
              <button
                type="button"
                onClick={clearFolder}
                className="rounded-md border border-border px-3 py-1.5 font-mono text-xs text-muted-foreground hover:bg-muted/30 hover:text-foreground transition-colors"
              >
                Change
              </button>
            )}
            <button
              type="button"
              onClick={handleAnalyze}
              disabled={isScanning || !projectName.trim() || sourceFiles.length === 0}
              className="rounded-md bg-primary px-4 py-1.5 font-mono text-xs font-semibold text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50 transition-colors"
            >
              {isScanning ? 'Scanning...' : 'Analyze Folder'}
            </button>
          </div>
        </div>
      )}

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
