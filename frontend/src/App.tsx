import { useCallback, useEffect, useRef, useState } from 'react';
import { api, type Provider, type Scan, type Tool } from './api';
import { ScanForm } from './components/ScanForm';
import { ScanList } from './components/ScanList';
import { ScanDetail } from './components/ScanDetail';
import { StatusDot } from './components/primitives';
import Aurora from './components/reactbits/Aurora';
import DecryptedText from './components/reactbits/DecryptedText';
import ShinyText from './components/reactbits/ShinyText';
import GradientText from './components/reactbits/GradientText';
import ClickSpark from './components/reactbits/ClickSpark';

const LIVE = new Set(['queued', 'running']);

export default function App() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [defaultProvider, setDefaultProvider] = useState('none');
  const [tools, setTools] = useState<Tool[]>([]);
  const [openScan, setOpenScan] = useState<string | null>(null);
  const [offline, setOffline] = useState(false);

  const timer = useRef<number | undefined>(undefined);

  const loadScans = useCallback(async () => {
    try {
      const rows = await api.scans();
      setScans(rows);
      setOffline(false);

      // Poll only while something is actually in flight.
      window.clearTimeout(timer.current);
      if (rows.some((s) => LIVE.has(s.status))) {
        timer.current = window.setTimeout(loadScans, 2500);
      }
    } catch {
      setOffline(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(loadScans, 5000);
    }
  }, []);

  useEffect(() => {
    api
      .providers()
      .then((r) => {
        setProviders(r.providers);
        setDefaultProvider(r.default);
      })
      .catch(() => setOffline(true));
    api.tools().then((r) => setTools(r.tools)).catch(() => undefined);
    loadScans();
    return () => window.clearTimeout(timer.current);
  }, [loadScans]);

  const ready = tools.filter((t) => t.available).length;
  const aiProviders = providers.filter((p) => p.key !== 'none');
  const aiReady = aiProviders.filter((p) => p.available);

  return (
    <ClickSpark sparkColor="#ff2e63" sparkSize={8} sparkRadius={18} sparkCount={7} duration={420}>
      <div className="relative min-h-screen">
        {/* Aurora sits behind everything and never intercepts clicks. */}
        <div className="pointer-events-none fixed inset-x-0 top-0 h-[420px] opacity-55">
          <Aurora colorStops={['#ff2e63', '#7a2ff2', '#4d9fff']} amplitude={0.9} blend={0.6} speed={0.4} />
        </div>
        <div className="pointer-events-none fixed inset-x-0 top-0 h-[420px] bg-gradient-to-b from-transparent to-base" />

        <div className="relative mx-auto max-w-[1400px] px-5 pb-20 sm:px-8">
          <header className="flex flex-wrap items-end justify-between gap-4 pt-12 pb-8">
            <div>
              <h1 className="text-[2.1rem] leading-none font-bold tracking-tight">
                <GradientText colors={['#ff2e63', '#ff6b8f', '#7a2ff2', '#ff2e63']} animationSpeed={9}>
                  vapt-ai
                </GradientText>
              </h1>
              <p className="mt-2 font-mono text-[0.82rem] text-dim">
                <DecryptedText
                  text="automated vulnerability assessment for git repositories"
                  animateOn="view"
                  sequential
                  speed={26}
                  revealDirection="start"
                  characters="ABCDEFGHIJKLMNOPQRSTUVWXYZ!<>-_\\/[]{}—=+*^?#"
                  className="text-dim"
                  encryptedClassName="text-faint/60"
                />
              </p>
            </div>

            <div className="flex flex-col items-end gap-1.5 text-[0.78rem]">
              <span className="flex items-center gap-2">
                <StatusDot color={offline ? '#ff2e63' : '#2ee6a8'} live={!offline} />
                {offline ? (
                  <span className="text-crit">API unreachable</span>
                ) : (
                  <ShinyText
                    // Until /api/tools answers, say so rather than claiming 0.
                    text={
                      tools.length
                        ? `${ready}/${tools.length} scanners ready`
                        : 'detecting scanners…'
                    }
                    speed={4}
                    color="#9096a3"
                    shineColor="#ffffff"
                    className="text-[0.78rem]"
                  />
                )}
              </span>
              <span className="text-faint">
                {aiReady.length
                  ? `${aiReady.length} of ${aiProviders.length} AI engines configured`
                  : 'no AI engine configured — scanners only'}
              </span>
            </div>
          </header>

          <main className="grid gap-5 lg:grid-cols-[360px_1fr] lg:items-start">
            <div className="grid gap-5">
              <ScanForm
                providers={providers}
                defaultProvider={defaultProvider}
                onCreated={loadScans}
              />
              <ToolPanel tools={tools} />
            </div>

            <section className="panel p-5">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="eyebrow">Assessments</h2>
                <button
                  onClick={loadScans}
                  className="rounded-lg border border-edge px-3 py-1 text-[0.76rem] text-faint transition hover:border-edge-hot hover:text-ink"
                >
                  Refresh
                </button>
              </div>
              <ScanList scans={scans} onOpen={setOpenScan} />
            </section>
          </main>
        </div>

        {openScan && (
          <ScanDetail
            scanId={openScan}
            onClose={() => setOpenScan(null)}
            onDeleted={() => {
              setOpenScan(null);
              loadScans();
            }}
          />
        )}
      </div>
    </ClickSpark>
  );
}

function ToolPanel({ tools }: { tools: Tool[] }) {
  return (
    <div className="panel p-5">
      <h2 className="eyebrow mb-3">Scanners</h2>
      <div className="grid gap-1.5">
        {tools.length === 0 && <p className="text-[0.78rem] text-faint">Detecting…</p>}
        {tools.map((tool) => (
          <div
            key={tool.name}
            title={tool.available ? tool.version || tool.description : tool.install_hint}
            className={`flex items-baseline gap-2 rounded-lg bg-base px-3 py-1.5 text-[0.8rem] ${
              tool.available ? '' : 'opacity-45'
            }`}
          >
            <span className="font-medium text-ink">{tool.name}</span>
            <span className="text-[0.7rem] text-faint">{tool.category}</span>
            <span
              className={`ml-auto text-[0.7rem] ${tool.available ? 'text-good' : 'text-faint'}`}
            >
              {tool.available ? 'ready' : 'missing'}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
