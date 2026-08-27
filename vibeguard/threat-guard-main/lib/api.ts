import type { ReportDetail } from '@/lib/threat-data'

const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`, options)
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.detail ?? `API request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export async function fetchLatestReport(): Promise<ReportDetail | null> {
  const reports = await request<Array<{ id: string }>>('/api/reports')
  if (reports.length === 0) return null
  return request<ReportDetail>(`/api/reports/${reports[0].id}`)
}

export async function scanProject(projectName: string, file: File): Promise<ReportDetail> {
  const formData = new FormData()
  formData.append('project_name', projectName)
  formData.append('file', file)
  return request<ReportDetail>('/api/scan', { method: 'POST', body: formData })
}

export async function analyzeSource(projectName: string, files: Array<{ filename: string; source_code: string }>): Promise<ReportDetail> {
  return request<ReportDetail>('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ project_name: projectName, files }),
  })
}