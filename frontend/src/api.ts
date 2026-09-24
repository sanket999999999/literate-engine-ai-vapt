/** Typed client for the vapt-ai REST API. */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Category = 'sast' | 'secret' | 'dependency' | 'iac';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export interface Provider {
  key: string;
  label: string;
  description: string;
  available: boolean;
  reason: string;
  models: string[];
  default_model: string;
  requires_key: string;
  local: boolean;
}

export interface Tool {
  name: string;
  category: Category;
  description: string;
  available: boolean;
  version: string;
  install_hint: string;
}

export interface ScannerRun {
  name: string;
  status: 'ok' | 'error' | 'skipped';
  findings: number;
  duration: number;
  message: string;
}

export interface Summary {
  total_findings: number;
  counts: Record<Severity, number>;
  raw_counts: Record<Severity, number>;
  confirmed: number;
  dismissed: number;
  needs_review: number;
  untriaged: number;
  risk_score: number;
  grade: string;
}

export interface TriageUsage {
  requests?: number;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  estimated_cost_usd?: number;
  provider?: string;
  provider_label?: string;
  model?: string;
  errors?: string[];
}

export interface Scan {
  id: string;
  repo_url: string;
  provider: string;
  branch: string;
  commit_sha: string;
  status: ScanStatus;
  stage: string;
  progress: number;
  error: string;
  deep_history: boolean;
  ai_triage: boolean;
  ai_provider: string;
  ai_model: string;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  languages: string[];
  scanner_runs: ScannerRun[];
  summary: Partial<Summary>;
  executive_summary: string;
  triage_usage: TriageUsage;
}

export interface Finding {
  id: number;
  fingerprint: string;
  scanner: string;
  category: Category;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  effective_severity: Severity;
  file_path: string;
  line_start: number;
  line_end: number;
  code_snippet: string;
  cwe: string[];
  cve: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  reference: string;
  corroborated_by: string[];
  triaged: boolean;
  verdict: '' | 'true_positive' | 'false_positive' | 'needs_review';
  confidence: string;
  ai_severity: string;
  attack_scenario: string;
  remediation: string;
  triage_rationale: string;
}

export interface NewScan {
  repo_url: string;
  branch?: string;
  deep_history?: boolean;
  ai_triage?: boolean;
  provider?: string;
  model?: string;
}

export class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (response.status === 204) return undefined as T;

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    // FastAPI puts the message in `detail`, sometimes as a validation array.
    const detail = (body as { detail?: unknown }).detail;
    throw new ApiError(
      typeof detail === 'string'
        ? detail
        : Array.isArray(detail)
          ? detail.map((d: { msg?: string }) => d.msg ?? String(d)).join('; ')
          : response.statusText || 'Request failed',
    );
  }
  return body as T;
}

export const api = {
  health: () =>
    request<{
      status: string;
      ai_triage: boolean;
      default_provider: string;
      max_concurrent_scans: number;
    }>('/api/health'),

  providers: () =>
    request<{ providers: Provider[]; default: string; available: number }>('/api/providers'),

  tools: () => request<{ tools: Tool[]; installed: number; total: number }>('/api/tools'),

  scans: () => request<{ scans: Scan[] }>('/api/scans').then((r) => r.scans),

  scan: (id: string) => request<Scan>(`/api/scans/${id}`),

  findings: (id: string, severity?: Severity | '') =>
    request<{ findings: Finding[]; count: number }>(
      `/api/scans/${id}/findings${severity ? `?severity=${severity}` : ''}`,
    ).then((r) => r.findings),

  create: (body: NewScan) =>
    request<{ id: string; status: string }>('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),

  remove: (id: string) => request<void>(`/api/scans/${id}`, { method: 'DELETE' }),

  reportUrl: (id: string, fmt: 'html' | 'md' | 'json') =>
    `/api/scans/${id}/report?fmt=${fmt}`,
};

/* ------------------------------------------------------------- formatting */

export function repoName(url: string): string {
  return url.replace(/\.git$/, '').split('/').slice(-2).join('/');
}

export function timeAgo(iso: string | null): string {
  if (!iso) return '';
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export const SEVERITY_CLASS: Record<Severity, string> = {
  CRITICAL: 'text-crit',
  HIGH: 'text-high',
  MEDIUM: 'text-med',
  LOW: 'text-low',
  INFO: 'text-info',
};

export const SEVERITY_HEX: Record<Severity, string> = {
  CRITICAL: '#ff2e63',
  HIGH: '#ff7a45',
  MEDIUM: '#f5c145',
  LOW: '#4d9fff',
  INFO: '#8b93a3',
};

export const CATEGORY_LABEL: Record<Category, string> = {
  sast: 'Code flaw',
  secret: 'Exposed secret',
  dependency: 'Vulnerable dependency',
  iac: 'Infra misconfig',
};

export function gradeHex(grade: string): string {
  return (
    { A: '#2ee6a8', B: '#7fd85a', C: '#f5c145', D: '#ff7a45', E: '#ff5a3c', F: '#ff2e63' }[
      grade
    ] ?? '#8b93a3'
  );
}
