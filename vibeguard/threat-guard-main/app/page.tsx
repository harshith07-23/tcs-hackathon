'use client'

import { useEffect, useState } from 'react';
import { DashboardHeader } from '@/components/dashboard-header';
import { MetricStrip } from '@/components/metric-strip';
import { RiskGauge } from '@/components/risk-gauge';
import { ArchitectureGraph } from '@/components/architecture-graph';
import { VulnerabilityCard } from '@/components/vulnerability-card';
import { SeverityBadge } from '@/components/severity-badge';
import { ProjectInput } from '@/components/project-input';
import { toVulnerability } from '@/lib/threat-data';
import type { ReportDetail, Vulnerability } from '@/lib/threat-data';
import { fetchLatestReport } from '@/lib/api';

export default function Page() {
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [vulnerabilitiesList, setVulnerabilitiesList] = useState<Vulnerability[]>([]);
  const [isLoading, setIsLoading] = useState(true);
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

  // Centralized state reset + apply for ANY new scan result
  function applyReport(newReport: ReportDetail) {
    setReport(newReport);
    setVulnerabilitiesList(newReport.findings.map(toVulnerability));
    setError('');
  }

  const criticalCount = report?.critical_count ?? vulnerabilitiesList.filter((v) => v.severity === 'critical').length;
  const highCount = report?.high_count ?? vulnerabilitiesList.filter((v) => v.severity === 'high').length;
  const securityScore = report?.overall_score ?? 100;
  const riskScore = 100 - securityScore;
  const riskSeverity = riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low';
  const metrics = report ? [
    { label: 'Total Findings', value: String(report.total_findings), delta: `${report.security_posture}`, trend: 'up' as const },
    { label: 'Files Analyzed', value: String(report.scan_metadata?.total_files ?? 0), delta: 'source', trend: 'up' as const },
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

      {/* ---- Unified Project Input Section ---- */}
      <section className="mt-6">
        <ProjectInput onScanComplete={(rawReport) => applyReport(rawReport as ReportDetail)} />
      </section>
    </main>
  );
}


