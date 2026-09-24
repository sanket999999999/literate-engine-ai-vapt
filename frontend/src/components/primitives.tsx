import type { ReactNode } from 'react';
import { SEVERITY_HEX, type Severity } from '../api';

/** Small pill used for severities, categories and scanner names. */
export function Pill({
  children,
  color,
  className = '',
}: {
  children: ReactNode;
  color?: string;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[0.7rem] font-medium ${className}`}
      style={
        color
          ? {
              color,
              // Tint from the same hue so the pill reads as one object.
              background: `color-mix(in oklab, ${color} 16%, transparent)`,
              border: `1px solid color-mix(in oklab, ${color} 32%, transparent)`,
            }
          : undefined
      }
    >
      {children}
    </span>
  );
}

export function SeverityPill({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <Pill color={SEVERITY_HEX[severity]}>
      {count !== undefined && <strong className="font-semibold">{count}</strong>}
      {severity.toLowerCase()}
    </Pill>
  );
}

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="rounded-full border border-edge bg-raised px-2 py-0.5 text-[0.68rem] text-dim">
      {children}
    </span>
  );
}

/** A dot that pulses only while something is actually happening. */
export function StatusDot({ color, live = false }: { color: string; live?: boolean }) {
  return (
    <span
      className={`inline-block size-2 shrink-0 rounded-full ${live ? 'animate-pulse-dot' : ''}`}
      style={{ background: color, boxShadow: `0 0 10px ${color}` }}
    />
  );
}

export function ProgressBar({ value, live }: { value: number; live?: boolean }) {
  return (
    <div className="relative h-1 w-full overflow-hidden rounded-full bg-edge">
      <div
        className={`h-full rounded-full transition-[width] duration-500 ${live ? 'animate-sweep relative overflow-hidden' : ''}`}
        style={{
          width: `${Math.max(2, value)}%`,
          background: 'linear-gradient(90deg,#4d9fff,#ff2e63)',
        }}
      />
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-10 text-center text-sm text-faint">{children}</p>;
}

/** Minimal Markdown for the model's narrative. Text is escaped before parse. */
export function Markdown({ text }: { text: string }) {
  return <div className="prose-report" dangerouslySetInnerHTML={{ __html: toHtml(text) }} />;
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );
}

function inline(value: string): string {
  return value
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`(.+?)`/g, '<code>$1</code>');
}

function toHtml(markdown: string): string {
  const out: string[] = [];
  let list: 'ul' | 'ol' | null = null;
  const closeList = () => {
    if (list) {
      out.push(`</${list}>`);
      list = null;
    }
  };

  for (const raw of escapeHtml(markdown).split('\n')) {
    const line = raw.trim();
    if (!line) {
      closeList();
      continue;
    }

    const heading = line.match(/^(#{2,4})\s+(.*)$/);
    if (heading) {
      closeList();
      const level = heading[1].length + 1;
      out.push(`<h${level}>${inline(heading[2])}</h${level}>`);
      continue;
    }

    const ordered = line.match(/^\d+[.)]\s+(.*)$/);
    const bullet = line.match(/^[-*]\s+(.*)$/);
    if (ordered || bullet) {
      const want = ordered ? 'ol' : 'ul';
      if (list !== want) {
        closeList();
        out.push(`<${want}>`);
        list = want;
      }
      out.push(`<li>${inline((ordered ?? bullet)![1])}</li>`);
      continue;
    }

    closeList();
    out.push(`<p>${inline(line)}</p>`);
  }
  closeList();
  return out.join('');
}
