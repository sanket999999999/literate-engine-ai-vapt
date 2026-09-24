import { useEffect, useState } from 'react';
import {
  CATEGORY_LABEL,
  SEVERITIES,
  SEVERITY_HEX,
  api,
  gradeHex,
  repoName,
  type Finding,
  type Scan,
  type Severity,
} from '../api';
import { Empty, Markdown, Pill, ProgressBar, Tag } from './primitives';
import CountUp from './reactbits/CountUp';

export function ScanDetail({
  scanId,
  onClose,
  onDeleted,
}: {
  scanId: string;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filter, setFilter] = useState<Severity | ''>('');
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;

    async function load() {
      try {
        const next = await api.scan(scanId);
        if (cancelled) return;
        setScan(next);

        if (next.status === 'completed') {
          const rows = await api.findings(scanId, filter);
          if (!cancelled) setFindings(rows);
        } else {
          // Keep the modal live while the scan is still running.
          timer = window.setTimeout(load, 2000);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load.');
      }
    }

    load();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [scanId, filter]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  async function remove() {
    if (!window.confirm('Delete this assessment and its report?')) return;
    try {
      await api.remove(scanId);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not delete.');
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 overflow-y-auto bg-black/70 p-4 backdrop-blur-sm sm:p-8"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="panel animate-rise mx-auto w-full max-w-4xl p-6 sm:p-8">
        <button
          onClick={onClose}
          aria-label="Close"
          className="float-right -mt-2 -mr-2 rounded-lg px-2 py-1 text-2xl leading-none text-faint transition hover:bg-raised hover:text-ink"
        >
          ×
        </button>

        {error && <p className="mb-4 text-sm text-crit">{error}</p>}
        {!scan ? (
          <Empty>Loading…</Empty>
        ) : (
          <>
            <Header scan={scan} />
            {scan.status !== 'completed' ? (
              <Running scan={scan} />
            ) : (
              <>
                <Stats scan={scan} />
                {scan.executive_summary && (
                  <section className="mt-7">
                    <h3 className="eyebrow mb-2">Analyst summary</h3>
                    <Markdown text={scan.executive_summary} />
                  </section>
                )}
                <Coverage scan={scan} />
                <section className="mt-7">
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <h3 className="eyebrow mr-auto">Findings</h3>
                    <FilterButton active={filter === ''} onClick={() => setFilter('')}>
                      All
                    </FilterButton>
                    {SEVERITIES.map((s) => (
                      <FilterButton
                        key={s}
                        active={filter === s}
                        color={SEVERITY_HEX[s]}
                        onClick={() => setFilter(s)}
                      >
                        {s.charAt(0) + s.slice(1).toLowerCase()}
                      </FilterButton>
                    ))}
                  </div>
                  {findings.length ? (
                    findings.map((f, i) => (
                      // A CSS animation, deliberately not AnimatedContent: that
                      // uses ScrollTrigger against the window, but this modal is
                      // its own scroll container, so the cards would never be
                      // revealed and would sit at opacity 0.
                      <div
                        key={f.id}
                        className="animate-rise"
                        style={{ animationDelay: `${Math.min(i * 0.02, 0.3)}s` }}
                      >
                        <FindingCard finding={f} />
                      </div>
                    ))
                  ) : (
                    <Empty>Nothing matches this filter.</Empty>
                  )}
                </section>
              </>
            )}

            <div className="mt-8 border-t border-edge pt-4">
              <button
                onClick={remove}
                className="rounded-lg border border-edge px-3 py-1.5 text-[0.8rem] text-faint transition hover:border-crit/50 hover:text-crit"
              >
                Delete assessment
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function Header({ scan }: { scan: Scan }) {
  return (
    <header>
      <h2 className="text-xl font-semibold tracking-tight">{repoName(scan.repo_url)}</h2>
      <p className="mt-1 font-mono text-[0.78rem] break-all text-faint">{scan.repo_url}</p>
      <p className="mt-1 text-[0.78rem] text-faint">
        {scan.branch && (
          <>
            branch <code className="text-dim">{scan.branch}</code> ·{' '}
          </>
        )}
        {scan.commit_sha && (
          <>
            commit <code className="text-dim">{scan.commit_sha.slice(0, 10)}</code> ·{' '}
          </>
        )}
        {scan.languages.join(', ') || 'unknown'}
      </p>
    </header>
  );
}

function Running({ scan }: { scan: Scan }) {
  return (
    <div className="mt-6">
      {scan.status === 'failed' ? (
        <p className="rounded-lg border border-crit/30 bg-crit/10 px-4 py-3 text-sm text-crit">
          {scan.error || 'Scan failed.'}
        </p>
      ) : (
        <>
          <ProgressBar value={scan.progress} live />
          <p className="mt-2 text-sm text-dim">{scan.stage}</p>
        </>
      )}
    </div>
  );
}

function Stats({ scan }: { scan: Scan }) {
  const s = scan.summary;
  const counts = (s?.counts ?? {}) as Record<Severity, number>;
  const usage = scan.triage_usage ?? {};

  return (
    <>
      <div className="mt-6 grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        <div className="rounded-xl border border-edge bg-raised/60 p-3">
          <div className="text-2xl font-bold" style={{ color: gradeHex(s?.grade ?? '') }}>
            {s?.grade ?? '–'}
          </div>
          <div className="eyebrow mt-0.5">
            risk <CountUp to={s?.risk_score ?? 0} duration={1.2} />
          </div>
        </div>
        {SEVERITIES.map((sev) => (
          <div key={sev} className="rounded-xl border border-edge bg-raised/60 p-3">
            <div className="text-2xl font-bold" style={{ color: SEVERITY_HEX[sev] }}>
              <CountUp to={counts[sev] ?? 0} duration={1.2} />
            </div>
            <div className="eyebrow mt-0.5">{sev}</div>
          </div>
        ))}
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[0.78rem] text-faint">
        <span>
          <strong className="text-dim">{s?.confirmed ?? 0}</strong> confirmed
        </span>
        <span>
          <strong className="text-dim">{s?.needs_review ?? 0}</strong> need review
        </span>
        <span>
          <strong className="text-dim">{s?.dismissed ?? 0}</strong> dismissed
        </span>
        <span>
          <strong className="text-dim">{s?.untriaged ?? 0}</strong> not triaged
        </span>
        {usage.provider_label && (
          <span className="ml-auto">
            {usage.provider_label} · {usage.model} · {usage.requests} requests ·{' '}
            {usage.estimated_cost_usd ? `$${usage.estimated_cost_usd}` : 'free'}
          </span>
        )}
        {scan.ai_provider === 'none' && <span className="ml-auto">scanners only, no AI triage</span>}
      </div>

      {(usage.errors ?? []).map((message, i) => (
        <p
          key={i}
          className="mt-2 rounded-lg border border-med/30 bg-med/10 px-3 py-2 text-[0.78rem] text-med"
        >
          {message}
        </p>
      ))}

      <div className="mt-5 flex flex-wrap gap-2">
        <a
          href={api.reportUrl(scan.id, 'html')}
          target="_blank"
          rel="noopener noreferrer"
          className="rounded-lg bg-brand px-4 py-2 text-[0.82rem] font-semibold text-white transition hover:bg-brand/85"
        >
          Open full report
        </a>
        <a
          href={api.reportUrl(scan.id, 'md')}
          className="rounded-lg border border-edge px-4 py-2 text-[0.82rem] text-dim transition hover:border-edge-hot hover:text-ink"
        >
          Markdown
        </a>
        <a
          href={api.reportUrl(scan.id, 'json')}
          className="rounded-lg border border-edge px-4 py-2 text-[0.82rem] text-dim transition hover:border-edge-hot hover:text-ink"
        >
          JSON
        </a>
      </div>
    </>
  );
}

function Coverage({ scan }: { scan: Scan }) {
  return (
    <section className="mt-7">
      <h3 className="eyebrow mb-2">Scanner coverage</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-[0.82rem]">
          <thead>
            <tr className="text-faint">
              <th className="hairline py-2 pr-3 text-left font-medium">Scanner</th>
              <th className="hairline py-2 pr-3 text-left font-medium">Status</th>
              <th className="hairline py-2 pr-3 text-right font-medium">Findings</th>
              <th className="hairline py-2 pr-3 text-right font-medium">Time</th>
              <th className="hairline py-2 text-left font-medium">Note</th>
            </tr>
          </thead>
          <tbody>
            {scan.scanner_runs.map((run) => (
              <tr key={run.name}>
                <td className="hairline py-2 pr-3 font-medium text-ink">{run.name}</td>
                <td className="hairline py-2 pr-3">
                  <Pill
                    color={
                      run.status === 'ok'
                        ? '#2ee6a8'
                        : run.status === 'error'
                          ? '#ff2e63'
                          : '#8b93a3'
                    }
                  >
                    {run.status}
                  </Pill>
                </td>
                <td className="hairline py-2 pr-3 text-right tabular-nums text-dim">
                  {run.findings}
                </td>
                <td className="hairline py-2 pr-3 text-right tabular-nums text-dim">
                  {run.duration}s
                </td>
                <td className="hairline py-2 text-faint">{run.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function FilterButton({
  active,
  color,
  onClick,
  children,
}: {
  active: boolean;
  color?: string;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-[0.74rem] transition ${
        active ? 'text-white' : 'border-edge text-faint hover:border-edge-hot hover:text-dim'
      }`}
      style={
        active
          ? { background: color ?? '#ff2e63', borderColor: color ?? '#ff2e63' }
          : undefined
      }
    >
      {children}
    </button>
  );
}

function FindingCard({ finding: f }: { finding: Finding }) {
  const color = SEVERITY_HEX[f.effective_severity];
  return (
    <article
      className="mb-2.5 rounded-xl border border-edge bg-raised/40 p-4"
      style={{ borderLeft: `3px solid ${color}` }}
    >
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h4 className="font-medium text-ink">{f.title}</h4>
        {f.file_path && (
          <code className="ml-auto font-mono text-[0.72rem] break-all text-faint">
            {f.file_path}
            {f.line_start ? `:${f.line_start}` : ''}
          </code>
        )}
      </div>

      <div className="mt-2 flex flex-wrap gap-1.5">
        <Pill color={color}>{f.effective_severity.toLowerCase()}</Pill>
        <Tag>{CATEGORY_LABEL[f.category] ?? f.category}</Tag>
        <Tag>{f.scanner}</Tag>
        {f.cwe.map((c) => (
          <Tag key={c}>{c}</Tag>
        ))}
        {f.corroborated_by.map((s) => (
          <Tag key={s}>also: {s}</Tag>
        ))}
        {f.triaged && (
          <Pill
            color={
              f.verdict === 'true_positive'
                ? '#ff2e63'
                : f.verdict === 'needs_review'
                  ? '#f5c145'
                  : '#8b93a3'
            }
          >
            {f.verdict.replace(/_/g, ' ')} · {f.confidence}
          </Pill>
        )}
      </div>

      {f.description && <Description text={f.description} />}

      {f.package && (
        <p className="mt-2 text-[0.82rem] text-dim">
          <span className="font-semibold text-ink">{f.package}</span> {f.installed_version} →{' '}
          {f.fixed_version || 'no fix published'}
        </p>
      )}

      {f.attack_scenario && (
        <div className="mt-2.5 rounded-lg border border-crit/20 bg-crit/8 px-3 py-2">
          <div className="eyebrow mb-1 !text-crit">Attack scenario</div>
          <p className="text-[0.84rem] leading-relaxed text-dim">{f.attack_scenario}</p>
        </div>
      )}

      {f.remediation && (
        <div className="mt-2 rounded-lg border border-good/20 bg-good/8 px-3 py-2">
          <div className="eyebrow mb-1 !text-good">Remediation</div>
          <p className="text-[0.84rem] leading-relaxed text-dim">{f.remediation}</p>
        </div>
      )}

      {f.code_snippet && (
        <pre className="mt-2.5 overflow-x-auto rounded-lg border border-edge bg-base p-3 font-mono text-[0.74rem] leading-relaxed text-dim">
          <code>{f.code_snippet}</code>
        </pre>
      )}
    </article>
  );
}

/** Advisory text runs to thousands of characters; show the gist, expand on demand. */
function Description({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const long = text.length > 320;

  return (
    <div className="mt-2.5">
      <p
        className={`text-[0.84rem] leading-relaxed whitespace-pre-line text-dim ${
          long && !open ? 'line-clamp-3' : ''
        }`}
      >
        {text}
      </p>
      {long && (
        <button
          onClick={() => setOpen((v) => !v)}
          className="mt-1 text-[0.76rem] text-brand-soft transition hover:text-brand"
        >
          {open ? 'Show less' : 'Show more'}
        </button>
      )}
    </div>
  );
}
