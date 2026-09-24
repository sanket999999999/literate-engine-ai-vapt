import { useEffect, useMemo, useState } from 'react';
import { api, type Provider } from '../api';
import { StatusDot } from './primitives';
import StarBorder from './reactbits/StarBorder';

interface Props {
  providers: Provider[];
  defaultProvider: string;
  onCreated: () => void;
}

export function ScanForm({ providers, defaultProvider, onCreated }: Props) {
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('');
  const [deepHistory, setDeepHistory] = useState(false);
  const [providerKey, setProviderKey] = useState(defaultProvider);
  const [model, setModel] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // Follow the backend's default until the user picks for themselves.
  const [touched, setTouched] = useState(false);
  useEffect(() => {
    if (!touched) setProviderKey(defaultProvider);
  }, [defaultProvider, touched]);

  const selected = useMemo(
    () => providers.find((p) => p.key === providerKey),
    [providers, providerKey],
  );

  // Reset the model whenever the provider changes; models are provider-specific.
  useEffect(() => {
    setModel(selected?.default_model ?? '');
  }, [selected]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError('');
    setBusy(true);
    try {
      await api.create({
        repo_url: repoUrl.trim(),
        branch: branch.trim(),
        deep_history: deepHistory,
        ai_triage: providerKey !== 'none',
        provider: providerKey,
        model,
      });
      setRepoUrl('');
      setBranch('');
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start the scan.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="panel p-5">
      <h2 className="eyebrow mb-4">New assessment</h2>

      <label htmlFor="repo" className="mb-1.5 block text-xs font-semibold text-dim">
        Repository
      </label>
      <input
        id="repo"
        value={repoUrl}
        onChange={(e) => setRepoUrl(e.target.value)}
        placeholder="https://github.com/owner/repo"
        required
        autoComplete="off"
        spellCheck={false}
        className="mb-4 w-full rounded-lg border border-edge bg-base px-3 py-2 font-mono text-[0.82rem] text-ink outline-none transition placeholder:text-faint focus:border-brand/60 focus:ring-2 focus:ring-brand/20"
      />

      <label htmlFor="branch" className="mb-1.5 block text-xs font-semibold text-dim">
        Branch <span className="font-normal text-faint">optional</span>
      </label>
      <input
        id="branch"
        value={branch}
        onChange={(e) => setBranch(e.target.value)}
        placeholder="default branch"
        autoComplete="off"
        spellCheck={false}
        className="mb-5 w-full rounded-lg border border-edge bg-base px-3 py-2 font-mono text-[0.82rem] text-ink outline-none transition placeholder:text-faint focus:border-brand/60 focus:ring-2 focus:ring-brand/20"
      />

      <h2 className="eyebrow mb-2.5">Triage engine</h2>
      <div className="mb-4 grid gap-1.5">
        {providers.map((provider) => (
          <ProviderOption
            key={provider.key}
            provider={provider}
            checked={providerKey === provider.key}
            onSelect={() => {
              setTouched(true);
              setProviderKey(provider.key);
            }}
          />
        ))}
      </div>

      {selected && selected.models.length > 0 && (
        <>
          <label htmlFor="model" className="mb-1.5 block text-xs font-semibold text-dim">
            Model
          </label>
          <select
            id="model"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            disabled={!selected.available}
            className="mb-5 w-full rounded-lg border border-edge bg-base px-3 py-2 font-mono text-[0.8rem] text-ink outline-none transition focus:border-brand/60 focus:ring-2 focus:ring-brand/20 disabled:opacity-40"
          >
            {selected.models.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </>
      )}

      <label className="mb-5 flex cursor-pointer items-start gap-2.5 text-[0.82rem] text-dim">
        <input
          type="checkbox"
          checked={deepHistory}
          onChange={(e) => setDeepHistory(e.target.checked)}
          className="mt-0.5 size-3.5 shrink-0 accent-brand"
        />
        <span>
          Full history
          <span className="block text-[0.75rem] text-faint">
            Scan every commit for secrets that were later removed. Slower.
          </span>
        </span>
      </label>

      <StarBorder
        as="button"
        type="submit"
        disabled={busy || !repoUrl.trim()}
        color="#ff2e63"
        speed="4s"
        className="w-full disabled:opacity-50"
      >
        <span className="text-sm font-semibold">
          {busy ? 'Starting…' : 'Run assessment'}
        </span>
      </StarBorder>

      {error && (
        <p className="mt-3 rounded-lg border border-crit/30 bg-crit/10 px-3 py-2 text-[0.8rem] text-crit">
          {error}
        </p>
      )}
    </form>
  );
}

function ProviderOption({
  provider,
  checked,
  onSelect,
}: {
  provider: Provider;
  checked: boolean;
  onSelect: () => void;
}) {
  const disabled = !provider.available;
  return (
    <button
      type="button"
      onClick={onSelect}
      disabled={disabled}
      title={disabled ? provider.reason : provider.description}
      className={`group flex w-full items-start gap-2.5 rounded-lg border px-3 py-2 text-left transition ${
        checked
          ? 'border-brand/50 bg-brand/8'
          : 'border-edge bg-base hover:border-edge-hot'
      } ${disabled ? 'cursor-not-allowed opacity-45' : 'cursor-pointer'}`}
    >
      <span
        className={`mt-1 size-2.5 shrink-0 rounded-full border transition ${
          checked ? 'border-brand bg-brand' : 'border-edge-hot bg-transparent'
        }`}
      />
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="text-[0.82rem] font-medium text-ink">{provider.label}</span>
          {provider.local && provider.key !== 'none' && (
            <span className="rounded-full border border-good/30 bg-good/10 px-1.5 py-px text-[0.6rem] font-semibold tracking-wide text-good uppercase">
              local
            </span>
          )}
          {provider.available ? (
            <StatusDot color="#2ee6a8" />
          ) : (
            <StatusDot color="#636a78" />
          )}
        </span>
        <span className="mt-0.5 block text-[0.72rem] leading-snug text-faint">
          {disabled ? provider.reason : provider.description}
        </span>
      </span>
    </button>
  );
}
