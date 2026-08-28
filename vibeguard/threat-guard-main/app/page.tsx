'use client'

import { useEffect, useState } from 'react';
import { DashboardHeader } from '@/components/dashboard-header';
import { MetricStrip } from '@/components/metric-strip';
import { RiskGauge } from '@/components/risk-gauge';
import { ArchitectureGraph } from '@/components/architecture-graph';
import { VulnerabilityCard } from '@/components/vulnerability-card';
import { SeverityBadge } from '@/components/severity-badge';
import { toVulnerability } from '@/lib/threat-data';
import type { ReportDetail, Vulnerability } from '@/lib/threat-data';
import { analyzeSource, fetchLatestReport } from '@/lib/api';

export default function Page() {
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [vulnerabilitiesList, setVulnerabilitiesList] = useState<Vulnerability[]>([]);
  const [projectName, setProjectName] = useState('');
  const [filename, setFilename] = useState('source.py');
  const [sourceCode, setSourceCode] = useState('');
  const [sourceFiles, setSourceFiles] = useState<Array<{ filename: string; source_code: string }>>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchLatestReport()
      .then((latestReport) => {
        if (latestReport) {
          setReport(latestReport);
          setVulnerabilitiesList(latestReport.findings.map(toVulnerability));
        }
      })
      .catch((loadError: Error) => setError(loadError.message))
      .finally(() => setIsLoading(false));
  }, []);
  
  const criticalCount = report?.critical_count ?? vulnerabilitiesList.filter((v) => v.severity === 'critical').length;
  const highCount = report?.high_count ?? vulnerabilitiesList.filter((v) => v.severity === 'high').length;
  const securityScore = report?.overall_score ?? 100;
  const riskScore = 100 - securityScore;
  const riskSeverity = riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low';
  const metrics = report ? [
    { label: 'Total Findings', value: String(report.total_findings), delta: `${report.security_posture}`, trend: 'up' as const },
    { label: 'Files Analyzed', value: String(report.scan_metadata?.total_files ?? sourceFiles.length), delta: 'source', trend: 'up' as const },
    { label: 'Critical Findings', value: String(report.critical_count), delta: `${report.high_count} high`, trend: 'up' as const },
    { label: 'Scan Duration', value: `${report.scan_metadata?.scan_duration ?? 0}s`, delta: 'complete', trend: 'down' as const },
  ] : [];

  return (
    <main className="mx-auto min-h-screen max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
      <DashboardHeader />

      <section className="mt-6">
        <MetricStrip metrics={metrics} />
      </section>

      <section className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Risk score */}
        <div className="flex flex-col items-center justify-center rounded-md border border-border bg-card p-6">
          <div className="mb-4 flex w-full items-center justify-between">
            <h2 className="font-mono text-xs uppercase tracking-[0.2em] text-muted-foreground">
              Aggregate Risk
            </h2>
            <div className="flex gap-1.5">
              <SeverityBadge severity={riskSeverity} />
            </div>
          </div>
          <RiskGauge score={riskScore} />
          <div className="mt-6 grid w-full grid-cols-2 gap-3 border-t border-border pt-4">
            <div className="text-center">
              <p className="font-mono text-2xl font-bold tabular-nums text-critical">
                {criticalCount}
              </p>
              <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                Critical
              </p>
            </div>
            <div className="text-center">
              <p className="font-mono text-2xl font-bold tabular-nums text-high">{highCount}</p>
              <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                High
              </p>
            </div>
          </div>
        </div>

        {/* Architecture graph */}
        <div className="rounded-md border border-border bg-card p-4 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-foreground">System Architecture</h2>
              <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                Exposure & lateral movement map
              </p>
            </div>
          </div>
          <ArchitectureGraph findings={report?.findings ?? []} />
        </div>
      </section>

      <section className="mt-6">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-foreground">Vulnerability Intelligence</h2>
            <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              {isLoading ? 'Loading findings...' : report ? `${vulnerabilitiesList.length} findings · sorted by severity` : 'Submit source code to begin analysis'}
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {vulnerabilitiesList.map((vuln) => <VulnerabilityCard key={vuln.id} vuln={vuln} />)}
          {!isLoading && !report && <p className="text-sm text-muted-foreground">No analysis results yet.</p>}
        </div>
      </section>

      <section className="mt-6">
        <h2 className="text-sm font-semibold text-foreground">Analyze Source Code</h2>
        <form className="flex flex-col gap-2 mt-4" onSubmit={handleSubmit}>
          <label htmlFor="project-name" className="block text-sm font-medium text-foreground">
            Project name
            <input
              type="text"
              id="project-name"
              required
              value={projectName}
              className="mt-1 block w-full border border-border px-4 py-2 rounded-md"
              onChange={(e) => setProjectName(e.target.value)}
            />
          </label>
          <label htmlFor="source-files" className="block text-sm font-medium text-foreground">
            Source files (optional)
            <input
              type="file"
              id="source-files"
              multiple
              accept=".py,.js,.jsx,.ts,.tsx"
              className="mt-1 block w-full border border-border px-4 py-2 rounded-md text-sm"
              onChange={handleFiles}
            />
          </label>
          <label htmlFor="source-folder" className="block text-sm font-medium text-foreground">
            Folder (optional)
            <input
              type="file"
              id="source-folder"
              multiple
              // @ts-expect-error webkitdirectory is supported by Chromium browsers
              webkitdirectory=""
              className="mt-1 block w-full border border-border px-4 py-2 rounded-md text-sm"
              onChange={handleFiles}
            />
          </label>
          <label htmlFor="pasted-filename" className="block text-sm font-medium text-foreground">
            Pasted filename
            <input
              type="text"
              id="pasted-filename"
              value={filename}
              className="mt-1 block w-full border border-border px-4 py-2 rounded-md text-sm"
              onChange={(e) => setFilename(e.target.value)}
            />
          </label>
          <label htmlFor="source-code" className="block text-sm font-medium text-foreground">
            Source code
            <textarea
              id="source-code"
              value={sourceCode}
              rows={12}
              spellCheck={false}
              className="mt-1 block w-full resize-y border border-border bg-card px-4 py-3 font-mono text-sm"
              placeholder="Optional: paste one source file, then add more files or choose a folder above"
              onChange={(e) => setSourceCode(e.target.value)}
            />
          </label>
          <button type="submit" disabled={isScanning || (!sourceCode.trim() && sourceFiles.length === 0)} className="py-2 px-4 rounded-md bg-primary text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50">
            {isScanning ? 'Scanning...' : 'Run scan'}
          </button>
        </form>
        {error && <p className="mt-3 text-sm text-critical">{error}</p>}
      </section>
    </main>
  );

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!sourceCode.trim() && sourceFiles.length === 0) return;
    setIsScanning(true);
    setError('');
    try {
      if (sourceCode.trim() && !filename.trim()) {
        setError('Enter a filename for the pasted source code.');
        return;
      }
      const files = sourceCode.trim()
        ? [...sourceFiles, { filename, source_code: sourceCode }]
        : sourceFiles;
      const scannedReport = await analyzeSource(projectName, files);
      setReport(scannedReport);
      setVulnerabilitiesList(scannedReport.findings.map(toVulnerability));
      setProjectName('');
      setSourceCode('');
      setSourceFiles([]);
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : 'The scan failed.');
    } finally {
      setIsScanning(false);
    }
  }

  function handleFiles(e: React.ChangeEvent<HTMLInputElement>) {
    const selectedFiles = Array.from(e.target.files ?? []).filter((file) =>
      /\.(py|js|jsx|ts|tsx)$/i.test(file.name),
    );
    Promise.all(selectedFiles.map(async (file) => ({
      filename: file.webkitRelativePath || file.name,
      source_code: await file.text(),
    }))).then((newFiles) => setSourceFiles((existingFiles) => [...existingFiles, ...newFiles]));
  }
}

