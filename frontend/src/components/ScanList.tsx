import {
  SEVERITIES,
  gradeHex,
  repoName,
  timeAgo,
  type Scan,
  type Severity,
} from '../api';
import { Empty, ProgressBar, SeverityPill, StatusDot } from './primitives';
import SpotlightCard from './reactbits/SpotlightCard';
import CountUp from './reactbits/CountUp';
import AnimatedContent from './reactbits/AnimatedContent';

const STATUS_COLOR: Record<string, string> = {
  completed: '#2ee6a8',
  running: '#4d9fff',
  queued: '#8b93a3',
  failed: '#ff2e63',
};

export function ScanList({
  scans,
  onOpen,
}: {
  scans: Scan[];
  onOpen: (id: string) => void;
}) {
  if (!scans.length) {
    return <Empty>No assessments yet. Point it at a repository to begin.</Empty>;
  }

  return (
    <div className="grid gap-3">
      {scans.map((scan, i) => (
        <AnimatedContent
          key={scan.id}
          distance={24}
          duration={0.5}
          // Stagger the cards in, but cap the delay so a long list is not slow.
          delay={Math.min(i * 0.05, 0.4)}
          threshold={0.05}
        >
          <ScanCard scan={scan} onOpen={onOpen} />
        </AnimatedContent>
      ))}
    </div>
  );
}

function ScanCard({ scan, onOpen }: { scan: Scan; onOpen: (id: string) => void }) {
  const live = scan.status === 'running' || scan.status === 'queued';
  const counts = (scan.summary?.counts ?? {}) as Record<Severity, number>;
  const grade = scan.summary?.grade;

  return (
    <SpotlightCard
      className="cursor-pointer !border-edge !bg-panel/80 !p-0 transition hover:!border-edge-hot"
      spotlightColor="rgba(255, 46, 99, 0.12)"
    >
      <div
        role="button"
        tabIndex={0}
        onClick={() => onOpen(scan.id)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onOpen(scan.id);
          }
        }}
        className="p-4 outline-none focus-visible:ring-2 focus-visible:ring-brand/40"
      >
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <StatusDot color={STATUS_COLOR[scan.status] ?? '#8b93a3'} live={live} />
          <span className="font-medium text-ink">{repoName(scan.repo_url)}</span>

          {scan.branch && (
            <span className="font-mono text-[0.72rem] text-faint">{scan.branch}</span>
          )}

          {grade && scan.status === 'completed' && (
            <span
              className="rounded-md px-1.5 py-px text-[0.68rem] font-bold"
              style={{
                color: gradeHex(grade),
                background: `color-mix(in oklab, ${gradeHex(grade)} 15%, transparent)`,
              }}
            >
              {grade}
            </span>
          )}

          {scan.ai_provider && scan.ai_provider !== 'none' && (
            <span className="rounded-full border border-edge px-2 py-px text-[0.66rem] text-faint">
              {scan.ai_provider}
            </span>
          )}
          {scan.ai_provider === 'none' && (
            <span className="rounded-full border border-edge px-2 py-px text-[0.66rem] text-faint">
              scanners only
            </span>
          )}

          <span className="ml-auto text-[0.75rem] text-faint">
            {timeAgo(scan.created_at)}
          </span>
        </div>

        {scan.status === 'failed' ? (
          <p className="mt-2.5 line-clamp-2 text-[0.8rem] text-crit">
            {scan.error || 'Scan failed.'}
          </p>
        ) : live ? (
          <div className="mt-3">
            <ProgressBar value={scan.progress} live />
            <p className="mt-1.5 text-[0.78rem] text-dim">{scan.stage}</p>
          </div>
        ) : (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {SEVERITIES.filter((s) => counts[s]).map((s) => (
              <SeverityPill key={s} severity={s} count={counts[s]} />
            ))}
            {!SEVERITIES.some((s) => counts[s]) && (
              <span className="text-[0.78rem] text-good">No findings</span>
            )}
            {scan.summary?.risk_score !== undefined && (
              <span className="ml-auto text-[0.75rem] text-faint">
                risk <CountUp to={scan.summary.risk_score} duration={1} className="text-dim" />
                /100
              </span>
            )}
          </div>
        )}
      </div>
    </SpotlightCard>
  );
}
