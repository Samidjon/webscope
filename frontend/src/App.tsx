import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDownToLine, Bug, ChevronDown, CircleHelp,
  Code2, Database, FileSearch, Filter, Globe2, History, Layers3,
  LockKeyhole, PanelLeft, RefreshCw, Search, ShieldCheck, Trash2,
  Zap,
} from 'lucide-react'

type FlowSummary = {
  id: string; captured_at: string; method: string; scheme: string; host: string;
  port: number | null; path: string; url: string; response_status: number | null;
  elapsed_ms: number | null; content_type: string | null; error: string | null;
}
type HeaderPair = [string, string]
type FlowDetail = FlowSummary & {
  http_version: string | null; client_ip: string | null; request_headers: HeaderPair[];
  request_body: string; response_reason: string | null; response_headers: HeaderPair[];
  response_body: string;
}
type Stats = { requests: number; hosts: number; issues: number }
type Health = { api: string; proxy: string; host: string }
type InspectTab = 'request' | 'response' | 'overview'

const methodClass = (method: string) => `method method-${method.toLowerCase()}`
const statusClass = (status: number | null, error?: string | null) => {
  if (error) return 'status status-error'
  if (status === null) return 'status status-pending'
  if (status >= 500) return 'status status-red'
  if (status >= 400) return 'status status-orange'
  if (status >= 300) return 'status status-blue'
  return 'status status-green'
}
const prettyDate = (value: string) => {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
const prettyBody = (body: string) => {
  if (!body) return '(empty body)'
  try { return JSON.stringify(JSON.parse(body), null, 2) } catch { return body }
}

function App() {
  const [flows, setFlows] = useState<FlowSummary[]>([])
  const [stats, setStats] = useState<Stats>({ requests: 0, hosts: 0, issues: 0 })
  const [health, setHealth] = useState<Health>({ api: 'checking', proxy: 'checking', host: '127.0.0.1' })
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [detail, setDetail] = useState<FlowDetail | null>(null)
  const [tab, setTab] = useState<InspectTab>('request')
  const [search, setSearch] = useState('')
  const [method, setMethod] = useState('ALL')
  const [status, setStatus] = useState('')
  const [showFilters, setShowFilters] = useState(false)
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [error, setError] = useState('')

  const query = useMemo(() => {
    const params = new URLSearchParams({ limit: '500', search, method })
    if (status) params.set('status', status)
    return params.toString()
  }, [search, method, status])

  const refresh = useCallback(async (spinner = false) => {
    if (spinner) setLoading(true)
    try {
      const [flowResponse, statsResponse, healthResponse] = await Promise.all([
        fetch(`/api/flows?${query}`), fetch('/api/stats'), fetch('/api/health'),
      ])
      if (!flowResponse.ok || !statsResponse.ok || !healthResponse.ok) throw new Error('Local API did not respond correctly')
      const [nextFlows, nextStats, nextHealth] = await Promise.all([flowResponse.json(), statsResponse.json(), healthResponse.json()]) as [FlowSummary[], Stats, Health]
      setFlows(nextFlows); setStats(nextStats); setHealth(nextHealth); setError(''); setLastUpdated(new Date())
      setSelectedId(current => {
        const stillExists = current && nextFlows.some(flow => flow.id === current)
        return stillExists ? current : (nextFlows[0]?.id ?? null)
      })
    } catch {
      setHealth({ api: 'offline', proxy: 'offline', host: '127.0.0.1' })
      setError('Cannot reach WebScope API. Make sure the backend is running.')
    } finally { if (spinner) setLoading(false) }
  }, [query])

  useEffect(() => { void refresh(true) }, [refresh])
  useEffect(() => {
    const interval = window.setInterval(() => void refresh(false), 2000)
    return () => window.clearInterval(interval)
  }, [refresh])

  useEffect(() => {
    if (!selectedId) { setDetail(null); return }
    let cancelled = false
    fetch(`/api/flows/${selectedId}`)
      .then(response => { if (!response.ok) throw new Error('Not found'); return response.json() })
      .then((value: FlowDetail) => { if (!cancelled) setDetail(value) })
      .catch(() => { if (!cancelled) setDetail(null) })
    return () => { cancelled = true }
  }, [selectedId, flows])

  const clearHistory = async () => {
    if (!window.confirm('Clear the saved HTTP history? This cannot be undone.')) return
    try {
      await fetch('/api/flows', { method: 'DELETE' })
      setSelectedId(null); setDetail(null)
      await refresh(true)
    } catch { setError('Could not clear history.') }
  }

  const exportHistory = () => {
    const blob = new Blob([JSON.stringify(flows, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url; link.download = `webscope-history-${new Date().toISOString().slice(0, 10)}.json`
    link.click(); URL.revokeObjectURL(url)
  }

  const selectedSummary = flows.find(flow => flow.id === selectedId) ?? null
  const detailHeaders = tab === 'response' ? (detail?.response_headers ?? []) : (detail?.request_headers ?? [])
  const detailBody = tab === 'response' ? (detail?.response_body ?? '') : (detail?.request_body ?? '')

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-mark"><ShieldCheck size={22} strokeWidth={2.1} /></div>
          <div className="brand-copy"><strong>WebScope</strong><span>WEB SECURITY WORKBENCH</span></div>
          <button className="icon-button sidebar-collapse" title="Collapse sidebar" aria-label="Collapse sidebar"><PanelLeft size={17} /></button>
        </div>
        <div className="workspace-select"><div className="workspace-avatar">L</div><div className="workspace-name"><strong>Local workspace</strong><span>Personal project</span></div><ChevronDown size={15} /></div>
        <div className="nav-label">WORKSPACE</div>
        <nav className="nav-stack">
          <button className="nav-item active"><Activity size={17} /><span>Proxy history</span><span className="nav-count">{flows.length}</span></button>
          <button className="nav-item disabled" title="Coming in a future step"><Zap size={17} /><span>Repeater</span><span className="soon">SOON</span></button>
          <button className="nav-item disabled" title="Coming in a future step"><Bug size={17} /><span>Passive scanner</span><span className="soon">SOON</span></button>
          <button className="nav-item disabled" title="Coming in a future step"><Globe2 size={17} /><span>Target map</span><span className="soon">SOON</span></button>
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-card"><div className="privacy-title"><LockKeyhole size={15} /> Local-first capture</div><p>History is saved on this computer. Common credential headers and sensitive fields are masked automatically.</p></div>
          <a className="help-link" href="https://docs.mitmproxy.org/stable/" target="_blank" rel="noreferrer"><CircleHelp size={16} /> Proxy documentation <ArrowDownToLine size={13} className="external-icon" /></a>
          <div className="version-row"><span className="version-dot" /> WebScope <span>v0.1.0 MVP</span></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><span className="crumb-separator">/</span><strong>Proxy history</strong></div>
          <div className="topbar-right">
            <span className={`connection-pill ${health.proxy === 'online' ? 'is-connected' : ''}`}><span className="connection-dot" /> Proxy {health.proxy === 'online' ? 'online' : 'offline'}</span>
            <button className="icon-button" onClick={() => void refresh(true)} title="Refresh" aria-label="Refresh"><RefreshCw size={16} className={loading ? 'spin' : ''} /></button>
            <div className="user-avatar">WS</div>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading">
            <div><div className="eyebrow"><span className="eyebrow-mark" /> TRAFFIC ANALYSIS</div><h1>Proxy history</h1><p>Inspect HTTP requests and responses passing through your local proxy.</p></div>
            <div className="heading-actions"><button className="button secondary" onClick={exportHistory} disabled={!flows.length}><ArrowDownToLine size={15} /> Export view</button><button className="button danger-ghost" onClick={() => void clearHistory()} disabled={!stats.requests}><Trash2 size={15} /> Clear history</button></div>
          </section>

          {error && <div className="error-banner"><AlertTriangle size={16} /><span>{error}</span></div>}

          <section className="stats-grid">
            <div className="stat-card"><div className="stat-icon purple"><History size={17} /></div><div className="stat-label">Captured requests</div><div className="stat-value">{stats.requests.toLocaleString()}</div><div className="stat-foot"><span className="mini-dot purple-dot" /> Stored locally</div></div>
            <div className="stat-card"><div className="stat-icon blue"><Globe2 size={17} /></div><div className="stat-label">Unique hosts</div><div className="stat-value">{stats.hosts.toLocaleString()}</div><div className="stat-foot">Across captured traffic</div></div>
            <div className="stat-card"><div className="stat-icon amber"><AlertTriangle size={17} /></div><div className="stat-label">HTTP errors</div><div className="stat-value">{stats.issues.toLocaleString()}</div><div className="stat-foot">4xx, 5xx, or connection errors</div></div>
            <div className="stat-card status-card"><div className="stat-icon green"><ShieldCheck size={17} /></div><div className="stat-label">Capture engine</div><div className="stat-value status-value">{health.proxy === 'online' ? 'Running' : 'Offline'}</div><div className="stat-foot"><span className={`mini-dot ${health.proxy === 'online' ? 'green-dot' : 'red-dot'}`} /> 127.0.0.1:8080</div></div>
          </section>

          <section className="history-panel">
            <div className="panel-heading"><div className="panel-title-group"><div className="section-icon"><Layers3 size={17} /></div><div><h2>HTTP history</h2><p>Most recent requests first <span className="muted-separator">·</span> auto-refreshes every 2 seconds</p></div></div><div className="panel-meta"><span className="live-indicator"><span /> LIVE</span><span>{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}` : 'Waiting for data'}</span></div></div>
            <div className="toolbar"><div className="search-field"><Search size={16} /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search host, path, method…" aria-label="Search history" /><kbd>⌘ K</kbd></div><div className="toolbar-actions"><button className={`button filter-button ${showFilters ? 'is-open' : ''}`} onClick={() => setShowFilters(value => !value)}><Filter size={15} /> Filters {(method !== 'ALL' || status) && <span className="filter-active-dot" />}</button><button className="icon-button refresh-button" onClick={() => void refresh(true)} title="Refresh history" aria-label="Refresh history"><RefreshCw size={16} className={loading ? 'spin' : ''} /></button></div></div>
            {showFilters && <div className="filter-row"><label>Method<select value={method} onChange={event => setMethod(event.target.value)}><option value="ALL">All methods</option><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>OPTIONS</option><option>HEAD</option></select></label><label>Status<select value={status} onChange={event => setStatus(event.target.value)}><option value="">Any status</option><option value="2xx">2xx Success</option><option value="3xx">3xx Redirect</option><option value="4xx">4xx Client error</option><option value="5xx">5xx Server error</option><option value="pending">Pending</option><option value="error">Connection error</option></select></label><button className="text-button" onClick={() => { setMethod('ALL'); setStatus('') }}>Reset filters</button></div>}
            <div className="table-wrap"><table className="history-table"><thead><tr><th className="method-col">METHOD</th><th>HOST / PATH</th><th>STATUS</th><th>TYPE</th><th>TIME</th><th>LATENCY</th></tr></thead><tbody>
              {flows.map(flow => <tr key={flow.id} className={flow.id === selectedId ? 'selected-row' : ''} onClick={() => { setSelectedId(flow.id); setTab('request') }} tabIndex={0} onKeyDown={event => { if (event.key === 'Enter') { setSelectedId(flow.id); setTab('request') } }}>
                <td><span className={methodClass(flow.method)}>{flow.method}</span></td><td><div className="host-cell"><span className="host-name">{flow.host || '(unknown host)'}</span><span className="path-name">{flow.path || '/'}</span></div></td><td><span className={statusClass(flow.response_status, flow.error)}>{flow.error ? 'ERR' : flow.response_status ?? 'WAIT'}</span></td><td><span className="content-type">{(flow.content_type || '—').split(';')[0].replace('application/', '')}</span></td><td className="time-cell">{prettyDate(flow.captured_at)}</td><td className="latency-cell">{flow.elapsed_ms == null ? '—' : `${Math.round(flow.elapsed_ms)} ms`}</td>
              </tr>)}
            </tbody></table>
            {!flows.length && <div className="empty-state"><div className="empty-icon"><FileSearch size={23} /></div><h3>No captured requests yet</h3><p>Start the proxy, configure a test browser to use <code>127.0.0.1:8080</code>, then visit a site you own or are authorized to test.</p><div className="empty-steps"><span><b>1</b> Start proxy</span><span><b>2</b> Configure browser</span><span><b>3</b> Browse test site</span></div><div className="empty-note"><LockKeyhole size={14} /> HTTPS inspection requires trusting the local mitmproxy CA certificate.</div></div>}
            </div>
            <div className="table-footer"><span>Showing <strong>{flows.length}</strong> of <strong>{stats.requests}</strong> requests</span><span className="footer-right"><Database size={13} /> SQLite local storage</span></div>
          </section>

          <section className="inspector-panel">
            <div className="inspector-heading"><div className="panel-title-group"><div className="section-icon"><Code2 size={17} /></div><div><h2>Request inspector</h2><p>{selectedSummary ? <><span className={methodClass(selectedSummary.method)}>{selectedSummary.method}</span><span className="inspector-url">{selectedSummary.url}</span></> : 'Select a row to inspect the HTTP conversation'}</p></div></div><div className="inspector-tabs"><button className={tab === 'overview' ? 'active' : ''} onClick={() => setTab('overview')} disabled={!detail}>Overview</button><button className={tab === 'request' ? 'active' : ''} onClick={() => setTab('request')} disabled={!detail}>Request</button><button className={tab === 'response' ? 'active' : ''} onClick={() => setTab('response')} disabled={!detail}>Response</button></div></div>
            {!detail ? <div className="inspector-empty"><Code2 size={20} /><span>Choose a request from the history table to view its details.</span></div> : tab === 'overview' ? <div className="overview-grid"><div className="overview-item"><span>Full URL</span><code>{detail.url}</code></div><div className="overview-item"><span>Client</span><code>{detail.client_ip || '127.0.0.1'}</code></div><div className="overview-item"><span>HTTP version</span><code>{detail.http_version || '—'}</code></div><div className="overview-item"><span>Elapsed time</span><code>{detail.elapsed_ms == null ? 'Pending' : `${detail.elapsed_ms.toFixed(1)} ms`}</code></div><div className="overview-item"><span>Response</span><code className={statusClass(detail.response_status, detail.error)}>{detail.error || (detail.response_status ? `${detail.response_status} ${detail.response_reason || ''}` : 'Pending')}</code></div><div className="overview-item"><span>Content type</span><code>{detail.content_type || '—'}</code></div><div className="redaction-note"><LockKeyhole size={14} /> Sensitive headers and common secret fields are redacted before storage.</div></div> : <div className="message-view"><div className="message-toolbar"><span>{tab === 'request' ? 'Request' : 'Response'} headers <b>{detailHeaders.length}</b></span><span>{tab === 'request' ? new Blob([detail.request_body]).size : new Blob([detail.response_body]).size} body bytes (display estimate)</span></div><div className="message-columns"><div className="message-block"><div className="message-block-title">HEADERS <span>{detailHeaders.length}</span></div><pre>{detailHeaders.length ? detailHeaders.map(([key, value]) => `${key}: ${value}`).join('\n') : '(no headers recorded)'}</pre></div><div className="message-block body-block"><div className="message-block-title">BODY</div><pre>{prettyBody(detailBody)}</pre></div></div></div>}
          </section>
          <footer className="page-footer"><span><ShieldCheck size={14} /> Designed for authorized security testing</span><span>WebScope MVP <span className="muted-separator">·</span> Built for local analysis</span></footer>
        </div>
      </main>
    </div>
  )
}

export default App
