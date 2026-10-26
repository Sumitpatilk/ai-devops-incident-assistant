import { useCallback, useEffect, useState } from 'react'

type Source = 'github-actions' | 'docker' | 'kubernetes'
type VerificationStatus = 'not_run' | 'passed' | 'failed'

type Incident = {
  id: number
  source: string
  logs: string
  analysis_json: string | Record<string, unknown>
  fix_description?: string | null
  verification_status: VerificationStatus
  verification_notes?: string | null
  created_at?: string
  verified_at?: string | null
}

const panel = 'rounded-xl border border-slate-800 bg-slate-900/80'
const field =
  'w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500'
const primary =
  'rounded-lg bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:opacity-50'
const secondary =
  'rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50'

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers ?? {}),
    },
  })

  if (!response.ok) {
    const message = await response.text()
    throw new Error(message || `Request failed (${response.status})`)
  }

  return response.json() as Promise<T>
}

function normalizeIncidents(data: unknown): Incident[] {
  if (Array.isArray(data)) return data as Incident[]

  if (data && typeof data === 'object') {
    const response = data as {
      items?: unknown
      incidents?: unknown
    }

    if (Array.isArray(response.items)) {
      return response.items as Incident[]
    }

    if (Array.isArray(response.incidents)) {
      return response.incidents as Incident[]
    }
  }

  return []
}

function pretty(value: unknown): string {
  if (typeof value === 'string') {
    try {
      return JSON.stringify(JSON.parse(value), null, 2)
    } catch {
      return value
    }
  }
  return JSON.stringify(value ?? {}, null, 2)
}

function StatusPill({ status }: { status?: string }) {
  const style =
    status === 'passed'
      ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
      : status === 'failed'
        ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
        : 'border-amber-500/30 bg-amber-500/10 text-amber-300'

  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs ${style}`}>
      {(status || 'unknown').replaceAll('_', ' ')}
    </span>
  )
}

export default function App() {
  const [source, setSource] = useState<Source>('kubernetes')
  const [logs, setLogs] = useState('')
  const [fixDescription, setFixDescription] = useState('')
  const [analysis, setAnalysis] = useState<unknown>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selected, setSelected] = useState<Incident | null>(null)
  const [verificationStatus, setVerificationStatus] =
    useState<VerificationStatus>('not_run')
  const [verificationNotes, setVerificationNotes] = useState('')
  const [loading, setLoading] = useState(false)
  const [historyLoading, setHistoryLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [savingVerification, setSavingVerification] = useState(false)
  const [backendOnline, setBackendOnline] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const data = await api<unknown>('/api/v1/incidents?limit=50&offset=0')
      setIncidents(normalizeIncidents(data))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load incident history')
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  const checkHealth = useCallback(async () => {
    try {
      await api('/health')
      setBackendOnline(true)
    } catch {
      setBackendOnline(false)
    }
  }, [])

  useEffect(() => {
    void checkHealth()
    void loadHistory()
  }, [checkHealth, loadHistory])

  async function analyzeLogs() {
    setError('')
    setNotice('')
    setAnalysis(null)
    setSelected(null)

    if (!logs.trim()) {
      setError('Please paste logs before starting the analysis.')
      return
    }

    setLoading(true)
    try {
      const result = await api<unknown>('/api/v1/analyze', {
        method: 'POST',
        body: JSON.stringify({ source, logs }),
      })
      setAnalysis(result)
      setNotice('Analysis completed. Review the findings before saving the incident.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setLoading(false)
    }
  }

  async function saveIncident() {
    setError('')
    setNotice('')
    if (!logs.trim()) {
      setError('Paste logs before saving an incident.')
      return
    }

    setSaving(true)
    try {
      const saved = await api<Incident>('/api/v1/incidents', {
        method: 'POST',
        body: JSON.stringify({
          source,
          logs,
          fix_description: fixDescription.trim() || null,
        }),
      })
      setSelected(saved)
      setVerificationStatus(saved.verification_status || 'not_run')
      setVerificationNotes(saved.verification_notes || '')
      setNotice(`Incident #${saved.id} saved to incident memory.`)
      await loadHistory()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save incident')
    } finally {
      setSaving(false)
    }
  }

  async function openIncident(id: number) {
    setError('')
    setNotice('')
    try {
      const detail = await api<Incident>(`/api/v1/incidents/${id}`)
      setSelected(detail)
      setSource(detail.source as Source)
      setLogs(detail.logs)
      setFixDescription(detail.fix_description || '')
      setVerificationStatus(detail.verification_status || 'not_run')
      setVerificationNotes(detail.verification_notes || '')
      setAnalysis(detail.analysis_json)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not open incident')
    }
  }

  async function updateVerification() {
    if (!selected) {
      setError('Save or select an incident before updating it.')
      return
    }

    setError('')
    setNotice('')
    setSavingVerification(true)

    try {
      await api<Incident>(
        `/api/v1/incidents/${selected.id}/fix`,
        {
          method: 'PUT',
          body: JSON.stringify({
            fix_description: fixDescription.trim() || null,
          }),
        },
      )

      const updated = await api<Incident>(
        `/api/v1/incidents/${selected.id}/verification`,
        {
          method: 'POST',
          body: JSON.stringify({
            status: verificationStatus,
            notes: verificationNotes,
          }),
        },
      )

      setSelected(updated)
      setFixDescription(updated.fix_description || '')
      setVerificationStatus(updated.verification_status || verificationStatus)
      setVerificationNotes(updated.verification_notes || verificationNotes)
      setNotice(`Remediation notes and verification updated for incident #${selected.id}.`)
      await loadHistory()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update incident')
    } finally {
      setSavingVerification(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#080d18] text-slate-100">
      <header className="border-b border-slate-800 bg-slate-950/80">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center justify-between gap-4 px-5 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-400/30 bg-cyan-400/10 text-cyan-300">
              <svg viewBox="0 0 24 24" fill="none" className="h-6 w-6" stroke="currentColor" strokeWidth="1.7">
                <path d="M12 3 4.5 7v10L12 21l7.5-4V7L12 3Z" />
                <path d="m8 12 2.5 2.5L16 9" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight">OpsPilot</h1>
              <p className="text-xs text-slate-400">AI DevOps Incident Assistant</p>
            </div>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-2 text-xs">
            <span className={`h-2 w-2 rounded-full ${backendOnline ? 'bg-emerald-400' : 'bg-rose-400'}`} />
            <span className="text-slate-300">
              API {backendOnline ? 'Connected' : 'Offline'}
            </span>
            <button onClick={() => { void checkHealth(); void loadHistory() }} className="ml-1 text-cyan-300 hover:text-cyan-200">
              Refresh
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1500px] px-5 py-7 lg:px-8">
        <div className="mb-7 flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.22em] text-cyan-300">Incident operations</p>
            <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">Incident Command Center</h2>
            <p className="mt-2 max-w-2xl text-sm text-slate-400">
              Analyze pipeline and cluster logs, preserve evidence, and track verification.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className={`${panel} min-w-32 px-4 py-3`}>
              <p className="text-xs text-slate-400">Saved incidents</p>
              <p className="mt-1 text-2xl font-bold">{incidents.length}</p>
            </div>
            <div className={`${panel} min-w-32 px-4 py-3`}>
              <p className="text-xs text-slate-400">Verified passed</p>
              <p className="mt-1 text-2xl font-bold text-emerald-300">
                {incidents.filter((item) => item.verification_status === 'passed').length}
              </p>
            </div>
          </div>
        </div>

        {error && (
          <div role="alert" className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
            <strong className="mr-2">Error</strong>{error}
            <button className="float-right ml-3" onClick={() => setError('')}>×</button>
          </div>
        )}
        {notice && (
          <div role="status" className="mb-4 rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-sm text-cyan-100">
            {notice}
          </div>
        )}

        <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.45fr)_minmax(320px,0.8fr)]">
          <section className={`${panel} p-5 sm:p-6`}>
            <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="font-semibold">Log investigation</h3>
                <p className="mt-1 text-xs text-slate-400">Paste raw logs to run the rule-based analyzer.</p>
              </div>
              <span className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-400">Max 100 KB</span>
            </div>

            <label className="mb-2 block text-sm font-medium text-slate-300" htmlFor="source">
              Incident source
            </label>
            <select id="source" className={`${field} mb-4`} value={source} onChange={(e) => setSource(e.target.value as Source)}>
              <option value="github-actions">GitHub Actions / CI pipeline</option>
              <option value="docker">Docker build</option>
              <option value="kubernetes">Kubernetes / EKS</option>
            </select>

            <label className="mb-2 block text-sm font-medium text-slate-300" htmlFor="logs">
              Raw logs
            </label>
            <textarea
              id="logs"
              className={`${field} min-h-64 resize-y font-mono text-xs leading-6`}
              placeholder={'Example:\nWarning  Failed  pod/api-7bd9  Failed to pull image\nBack-off pulling image "example/api:latest"\n'}
              value={logs}
              maxLength={100000}
              onChange={(e) => setLogs(e.target.value)}
            />
            <div className="mt-2 flex justify-between text-xs text-slate-500">
              <span>Logs are sent to your local backend.</span>
              <span>{logs.length.toLocaleString()} / 100,000</span>
            </div>

            <div className="mt-5 flex flex-wrap gap-3">
              <button className={primary} onClick={analyzeLogs} disabled={loading || !backendOnline}>
                {loading ? 'Analyzing…' : 'Analyze logs'}
              </button>
              <button className={secondary} onClick={saveIncident} disabled={saving || !backendOnline || !logs.trim()}>
                {saving ? 'Saving…' : 'Save incident'}
              </button>
              <button className={secondary} onClick={() => {
                setLogs('')
                setAnalysis(null)
                setFixDescription('')
                setSelected(null)
                setNotice('')
                setError('')
              }}>
                Clear
              </button>
            </div>

            {analysis !== null && (
              <div className="mt-7 border-t border-slate-800 pt-5">
                <div className="mb-3 flex items-center justify-between gap-3">
                  <h3 className="font-semibold">Analysis output</h3>
                  <span className="text-xs text-amber-300">Pattern-based findings</span>
                </div>
                <pre className="max-h-[460px] overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-6 text-slate-300">
                  {pretty(analysis)}
                </pre>
                <p className="mt-3 text-xs leading-5 text-slate-500">
                  Findings are based on detected log patterns; confirm the root cause using the actual environment and evidence.
                </p>
              </div>
            )}
          </section>

          <div className="space-y-6">
            <section className={`${panel} p-5`}>
              <div className="mb-4">
                <h3 className="font-semibold">Incident memory</h3>
                <p className="mt-1 text-xs text-slate-400">Recent incidents saved in SQLite.</p>
              </div>
              {historyLoading && <p className="text-sm text-slate-400">Loading history…</p>}
              {!historyLoading && incidents.length === 0 && (
                <div className="rounded-lg border border-dashed border-slate-700 px-4 py-8 text-center">
                  <p className="text-sm text-slate-300">No saved incidents yet</p>
                  <p className="mt-1 text-xs text-slate-500">Analyze and save logs to build incident history.</p>
                </div>
              )}
              <div className="max-h-[440px] space-y-2 overflow-y-auto">
                {incidents.map((incident) => (
                  <button
                    key={incident.id}
                    onClick={() => void openIncident(incident.id)}
                    className={`w-full rounded-lg border p-3 text-left transition ${
                      selected?.id === incident.id
                        ? 'border-cyan-500/50 bg-cyan-500/5'
                        : 'border-slate-800 bg-slate-950/60 hover:border-slate-600'
                    }`}
                  >
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold">Incident #{incident.id}</span>
                      <StatusPill status={incident.verification_status} />
                    </div>
                    <div className="flex items-center justify-between gap-2 text-xs text-slate-400">
                      <span>{incident.source}</span>
                      <span>{incident.created_at ? new Date(incident.created_at).toLocaleString() : ''}</span>
                    </div>
                    <p className="mt-2 line-clamp-2 break-all font-mono text-xs text-slate-500">
                      {incident.logs.slice(0, 140)}
                    </p>
                  </button>
                ))}
              </div>
              <button className={`${secondary} mt-3 w-full`} onClick={() => void loadHistory()} disabled={historyLoading}>
                {historyLoading ? 'Refreshing…' : 'Refresh history'}
              </button>
            </section>

            <section className={`${panel} p-5`}>
              <div className="mb-4 flex items-start justify-between gap-3">
                <div>
                  <h3 className="font-semibold">Verification tracking</h3>
                  <p className="mt-1 text-xs text-slate-400">Record the outcome after you test a fix.</p>
                </div>
                {selected && <StatusPill status={selected.verification_status} />}
              </div>

              {selected ? (
                <p className="mb-4 text-xs text-slate-400">Selected incident: <strong className="text-slate-200">#{selected.id}</strong></p>
              ) : (
                <p className="mb-4 rounded-lg bg-slate-950 p-3 text-xs leading-5 text-slate-400">
                  Save a new incident or select one from history to update its verification status.
                </p>
              )}

              <label className="mb-2 block text-sm text-slate-300" htmlFor="verification-status">Status</label>
              <select
                id="verification-status"
                className={`${field} mb-4`}
                value={verificationStatus}
                onChange={(e) => setVerificationStatus(e.target.value as VerificationStatus)}
              >
                <option value="not_run">Not run</option>
                <option value="passed">Passed</option>
                <option value="failed">Failed</option>
              </select>

              <label className="mb-2 block text-sm text-slate-300" htmlFor="verification-notes">Verification notes</label>
              <textarea
                id="verification-notes"
                className={`${field} min-h-24 resize-y`}
                placeholder="What did you test? Include evidence or command output."
                value={verificationNotes}
                onChange={(e) => setVerificationNotes(e.target.value)}
              />

              <label className="mb-2 mt-4 block text-sm text-slate-300" htmlFor="fix-description">Fix / remediation notes</label>
              <textarea
                id="fix-description"
                className={`${field} min-h-20 resize-y`}
                placeholder="Describe the fix, if known."
                value={fixDescription}
                onChange={(e) => setFixDescription(e.target.value)}
              />

              <button className={`${primary} mt-4 w-full`} onClick={updateVerification} disabled={!selected || savingVerification}>
                {savingVerification ? 'Updating…' : 'Update verification'}
              </button>
              <p className="mt-3 text-xs leading-5 text-slate-500">
                Saves remediation notes and verification status. It does not run tests or deploy changes automatically.
              </p>
            </section>
          </div>
        </div>

        <footer className="mt-8 flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 py-5 text-xs text-slate-500">
          <span>OpsPilot · Local-first incident investigation</span>
          <span>Rule-based analysis · SQLite memory · No automatic production fixes</span>
        </footer>
      </main>
    </div>
  )
}
