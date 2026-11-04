import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Input, Spinner } from "../components/ui";
import { formatBytes } from "./StatsPage";

type Status = components["schemas"]["ServerStatus"];
type Service = components["schemas"]["ServiceState"];
type JobItem = components["schemas"]["JobItem"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";
const th = "px-4 py-3 font-medium";
const head = "border-b border-slate-200 text-slate-500 dark:border-slate-800";
const row = "border-t border-slate-100 dark:border-slate-800";

function ago(iso: string) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return "now";
  if (s < 5400) return `${Math.round(s / 60)} min`;
  if (s < 129600) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} d`;
}

function uptime(secs: number) {
  const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
}

function Meter({ value, max, label }: { value: number; max: number; label: string }) {
  return <meter className="h-2 w-full" min={0} max={Math.max(max, 1)} value={value} high={max * 0.8} optimum={0} aria-label={label} />;
}

function useStatus() {
  return useQuery({ queryKey: ["server-status"], queryFn: () => unwrap(api.GET("/server/status")), retry: false, refetchInterval: 10_000 });
}

/** The admin's dashboard: load, memory, disks, processes, accounts (ADM-SVC-03, 05). */
export function ServerDashboard() {
  const { t } = useTranslation();
  const q = useStatus();
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  const s = q.data;
  const memUsed = s.mem_total - s.mem_available;
  const failed = s.jobs.failed ?? 0;
  const [l1 = 0, l5 = 0, l15 = 0] = s.load;
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardTitle>{t("server.cpu")}</CardTitle>
          <div className="text-3xl font-semibold">{s.cpu_percent.toFixed(0)}%</div>
          <Meter value={s.cpu_percent} max={100} label={t("server.cpu")} />
          <p className="mt-2 text-xs text-slate-500">{t("server.cores", { n: s.cores })}</p>
        </Card>
        <Card>
          <CardTitle>{t("server.load")}</CardTitle>
          <div className="text-3xl font-semibold">{l1.toFixed(2)}</div>
          <Meter value={l1} max={s.cores} label={t("server.load")} />
          <p className="mt-2 text-xs text-slate-500">{t("server.load5", { a: l5.toFixed(2), b: l15.toFixed(2) })}</p>
        </Card>
        <Card>
          <CardTitle>{t("server.memory")}</CardTitle>
          <div className="text-3xl font-semibold">{formatBytes(memUsed)}</div>
          <Meter value={memUsed} max={s.mem_total} label={t("server.memory")} />
          <p className="mt-2 text-xs text-slate-500">
            {t("server.ofTotal", { total: formatBytes(s.mem_total) })}
            {s.swap_total > 0 && ` · ${t("server.swap", { used: formatBytes(s.swap_total - s.swap_free), total: formatBytes(s.swap_total) })}`}
          </p>
        </Card>
        <Card>
          <CardTitle>{t("server.uptime")}</CardTitle>
          <div className="text-3xl font-semibold">{uptime(s.uptime_seconds)}</div>
          <p className="mt-2 text-xs text-slate-500">
            <Link to="/jobs" className="underline">{t("server.jobsSummary", { queued: s.jobs.queued ?? 0, running: s.jobs.running ?? 0 })}</Link>
          </p>
          {failed > 0 && <p className="mt-1 text-xs text-red-700 dark:text-red-400">{t("server.jobsFailed", { n: failed })}</p>}
        </Card>
      </div>

      <Card className="overflow-x-auto p-0">
        <div className="px-4 pt-4"><CardTitle>{t("server.disks")}</CardTitle></div>
        <table className="w-full text-left text-sm">
          <thead className={head}><tr>{["server.mount", "server.used", "server.inodes"].map((k) => <th key={k} className={th}>{t(k)}</th>)}</tr></thead>
          <tbody>
            {s.disks.map((d) => (
              <tr key={d.mount} className={row}>
                <td className="px-4 py-3"><div className="font-medium">{d.mount}</div><div className="text-xs text-slate-500">{d.device} · {d.fs}</div></td>
                <td className="w-1/3 px-4 py-3"><Meter value={d.used} max={d.total} label={d.mount} /><div className="text-xs text-slate-500">{formatBytes(d.used)} / {formatBytes(d.total)}</div></td>
                <td className="w-1/4 px-4 py-3"><Meter value={d.files_used} max={d.files} label={d.mount} /><div className="text-xs text-slate-500">{d.files_used.toLocaleString()} / {d.files.toLocaleString()}</div></td>
              </tr>
            ))}
            {s.disks.length === 0 && <tr><td colSpan={3} className="px-4 py-6 text-center text-slate-500">{t("server.noDisks")}</td></tr>}
          </tbody>
        </table>
      </Card>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card className="overflow-x-auto p-0">
          <div className="px-4 pt-4"><CardTitle>{t("server.topAccounts")}</CardTitle></div>
          <table className="w-full text-left text-sm">
            <thead className={head}><tr><th className={th}>{t("server.account")}</th><th className={th}>{t("server.diskUsed")}</th></tr></thead>
            <tbody>
              {s.accounts.slice(0, 10).map((a) => (
                <tr key={a.username} className={row}>
                  <td className="px-4 py-2 font-medium">{a.username}</td>
                  <td className="px-4 py-2">{formatBytes(a.bytes)}{a.partial && <span className="ml-1 text-xs text-slate-500">{t("server.atLeast")}</span>}</td>
                </tr>
              ))}
              {s.accounts.length === 0 && <tr><td colSpan={2} className="px-4 py-6 text-center text-slate-500">{s.accounts_computing ? t("server.measuring") : t("server.noAccounts")}</td></tr>}
            </tbody>
          </table>
          {s.accounts_at && <p className="px-4 py-2 text-xs text-slate-500">{t("server.measured", { ago: ago(s.accounts_at) })}{s.accounts_computing && ` · ${t("server.measuring")}`}</p>}
        </Card>
        <Card className="overflow-x-auto p-0">
          <div className="px-4 pt-4"><CardTitle>{t("server.topProcesses")}</CardTitle></div>
          <table className="w-full text-left text-sm">
            <thead className={head}><tr>{["server.process", "server.user", "server.cpuShort", "server.memShort"].map((k) => <th key={k} className={th}>{t(k)}</th>)}</tr></thead>
            <tbody>
              {s.procs.map((p) => (
                <tr key={p.pid} className={row}>
                  <td className="px-4 py-2"><span className="font-medium">{p.name}</span> <span className="text-xs text-slate-500">{p.pid}</span></td>
                  <td className="px-4 py-2">{p.user}</td><td className="px-4 py-2">{p.cpu_percent.toFixed(1)}%</td><td className="px-4 py-2">{formatBytes(p.rss)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>

      <Card>
        <CardTitle>{t("server.network")}</CardTitle>
        <p className="mb-2 text-xs text-slate-500">{t("server.sinceBoot")}</p>
        <div className="flex flex-wrap gap-6 text-sm">
          {s.net.map((n) => <div key={n.name}><span className="font-medium">{n.name}</span> ↓ {formatBytes(n.rx_bytes)} · ↑ {formatBytes(n.tx_bytes)}</div>)}
        </div>
      </Card>
    </div>
  );
}

/** Services and server information (ADM-SVC-01, 08). */
export function ServicesPage() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["server-services"], queryFn: () => unwrap(api.GET("/server/services")), retry: false, refetchInterval: 15_000 });
  const status = useStatus();
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("server.servicesTitle")}</h1>
      {q.isPending ? <Spinner /> : !q.data ? <ErrorAlert error={q.error} /> : (
        <Card className="overflow-x-auto p-0">
          <table className="w-full text-left text-sm">
            <thead className={head}><tr>{["server.service", "server.state", "server.boot", ""].map((k) => <th key={k} className={th}>{k && t(k)}</th>)}</tr></thead>
            <tbody>{q.data.items.map((s) => <ServiceRow key={s.id} s={s} />)}</tbody>
          </table>
        </Card>
      )}
      {status.data && <Info s={status.data} />}
    </div>
  );
}

function ServiceRow({ s }: { s: Service }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [showLog, setShowLog] = useState(false);
  const act = useMutation({
    mutationFn: (action: "start" | "stop" | "restart" | "reload" | "enable" | "disable") =>
      unwrap(api.POST("/server/services/{id}/{action}", { params: { path: { id: s.id, action } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["server-services"] }),
  });
  const running = s.state === "active";
  const color = !s.installed ? "text-slate-500" : running ? "text-green-700 dark:text-green-400" : s.state === "failed" ? "text-red-700 dark:text-red-400" : "text-amber-700 dark:text-amber-400";
  const confirm = (a: "stop" | "restart" | "disable") => window.confirm(t("server.confirmAction", { action: t(`server.${a}`), service: t(`server.names.${s.id}`) })) && act.mutate(a);
  return (
    <>
      <tr className={`${row} align-top`}>
        <td className="px-4 py-3"><div className="font-medium">{t(`server.names.${s.id}`)}</div><div className="text-xs text-slate-500">{s.unit || s.id}</div></td>
        <td className={`px-4 py-3 ${color}`}>{s.installed ? `${s.state}${s.sub_state && s.sub_state !== s.state ? ` (${s.sub_state})` : ""}` : t("server.notInstalled")}</td>
        <td className="px-4 py-3">{s.installed ? (s.enabled ? t("server.enabled") : t("server.disabled")) : ""}</td>
        <td className="whitespace-nowrap px-4 py-3 text-right">
          {s.installed && (
            <>
              {!running && <Button variant="ghost" disabled={act.isPending} onClick={() => act.mutate("start")}>{t("server.start")}</Button>}
              {running && !s.protected && <Button variant="ghost" disabled={act.isPending} onClick={() => confirm("restart")}>{t("server.restart")}</Button>}
              {running && !s.protected && <Button variant="ghost" disabled={act.isPending} onClick={() => confirm("stop")}>{t("server.stop")}</Button>}
              {!s.protected && <Button variant="ghost" disabled={act.isPending} onClick={() => (s.enabled ? confirm("disable") : act.mutate("enable"))}>{s.enabled ? t("server.disable") : t("server.enable")}</Button>}
              <Button variant="ghost" onClick={() => setShowLog(!showLog)}>{t("server.logs")}</Button>
            </>
          )}
        </td>
      </tr>
      {(act.error || showLog) && (
        <tr className="bg-slate-50 dark:bg-slate-900/50"><td colSpan={4} className="px-4 py-3">
          <ErrorAlert error={act.error} />
          {showLog && <ServiceLog id={s.id} />}
        </td></tr>
      )}
    </>
  );
}

function ServiceLog({ id }: { id: string }) {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["service-log", id], queryFn: () => unwrap(api.GET("/server/services/{id}/log", { params: { path: { id }, query: { lines: 100 } } })), retry: false });
  if (q.isPending) return <Spinner />;
  return (
    <div className="space-y-2">
      <ErrorAlert error={q.error} />
      <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-white p-3 font-mono text-xs dark:bg-slate-950">{q.data?.text || t("server.noLog")}</pre>
      <Button variant="ghost" onClick={() => void q.refetch()}>{t("stats.refresh")}</Button>
    </div>
  );
}

function Info({ s }: { s: Status }) {
  const { t } = useTranslation();
  const rows: [string, string][] = [
    ["server.hostname", s.hostname], ["server.os", s.os], ["server.kernel", `${s.kernel} (${s.arch})`], ["server.cpuModel", `${s.cpu_model} × ${s.cores}`],
    ["server.memory", formatBytes(s.mem_total)], ["server.xcp", s.xcp_version],
  ];
  return (
    <Card>
      <CardTitle>{t("server.info")}</CardTitle>
      <dl className="mb-4 grid gap-2 text-sm sm:grid-cols-[12rem_1fr]">
        {rows.map(([k, v]) => <div key={k} className="contents"><dt className="text-slate-500">{t(k)}</dt><dd>{v}</dd></div>)}
      </dl>
      <p className="mb-1 text-sm font-medium">{t("server.versions")}</p>
      <dl className="grid gap-1 text-sm sm:grid-cols-[12rem_1fr]">
        {s.versions.map((v) => <div key={v.package} className="contents"><dt className="text-slate-500">{v.package}</dt><dd className="font-mono text-xs">{v.version}</dd></div>)}
      </dl>
    </Card>
  );
}

/** The task queue (ADM-SVC-07). */
export function JobsPage() {
  const { t } = useTranslation();
  const [state, setState] = useState("");
  const [kind, setKind] = useState("");
  const [search, setSearch] = useState("");
  const q = useQuery({
    queryKey: ["server-jobs", state, search],
    queryFn: () => unwrap(api.GET("/server/jobs", { params: { query: { status: (state || undefined) as JobItem["status"] | undefined, kind: search || undefined, limit: 100 } } })),
    retry: false,
    refetchInterval: 5000,
  });
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("server.jobsTitle")}</h1>
      <form onSubmit={(e) => { e.preventDefault(); setSearch(kind); }} className="flex flex-wrap items-center gap-2 text-sm">
        <select aria-label={t("server.state")} className={selectClass} value={state} onChange={(e) => setState(e.target.value)}>
          <option value="">{t("server.allStates")}</option>
          {["queued", "running", "succeeded", "failed", "canceled"].map((x) => <option key={x} value={x}>{t(`server.job.${x}`)}</option>)}
        </select>
        <Input aria-label={t("server.kind")} className="max-w-xs" placeholder={t("server.kind")} value={kind} onChange={(e) => setKind(e.target.value)} />
        <Button type="submit" variant="secondary">{t("stats.show")}</Button>
      </form>
      {q.isPending ? <Spinner /> : !q.data ? <ErrorAlert error={q.error} /> : (
        <Card className="overflow-x-auto p-0">
          <table className="w-full text-left text-sm">
            <thead className={head}><tr>{["server.kind", "server.state", "server.attempts", "server.created", "server.error", ""].map((k) => <th key={k} className={th}>{t(k)}</th>)}</tr></thead>
            <tbody>
              {q.data.items.map((j) => <JobRow key={j.id} j={j} />)}
              {q.data.items.length === 0 && <tr><td colSpan={6} className="px-4 py-6 text-center text-slate-500">{t("server.noJobs")}</td></tr>}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

function JobRow({ j }: { j: JobItem }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const change = useMutation({
    mutationFn: (what: "cancel" | "retry") => unwrap(api.POST(what === "cancel" ? "/server/jobs/{id}/cancel" : "/server/jobs/{id}/retry", { params: { path: { id: j.id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["server-jobs"] }),
  });
  const color = j.status === "failed" ? "text-red-700 dark:text-red-400" : j.status === "succeeded" ? "text-green-700 dark:text-green-400" : "text-slate-600 dark:text-slate-300";
  return (
    <>
      <tr className={`${row} align-top`}>
        <td className="px-4 py-3 font-mono text-xs">{j.kind}</td>
        <td className={`px-4 py-3 ${color}`}>{t(`server.job.${j.status}`)}{j.status === "running" && ` ${j.progress}%`}</td>
        <td className="px-4 py-3">{j.attempts}/{j.max_attempts}</td>
        <td className="whitespace-nowrap px-4 py-3 text-xs">{new Date(j.created_at).toLocaleString()}</td>
        <td className="max-w-md break-words px-4 py-3 text-xs">{j.error}</td>
        <td className="whitespace-nowrap px-4 py-3 text-right">
          {(j.status === "queued" || j.status === "running") && <Button variant="ghost" disabled={change.isPending} onClick={() => change.mutate("cancel")}>{t("common.cancel")}</Button>}
          {(j.status === "failed" || j.status === "canceled") && <Button variant="ghost" disabled={change.isPending} onClick={() => change.mutate("retry")}>{t("server.retry")}</Button>}
        </td>
      </tr>
      {change.error && <tr><td colSpan={6} className="px-4 pb-3"><ErrorAlert error={change.error} /></td></tr>}
    </>
  );
}

/** Every session and the sign-in history (ADM-SEC-12). */
export function SessionsPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const sessions = useQuery({ queryKey: ["all-sessions"], queryFn: () => unwrap(api.GET("/server/sessions")), retry: false, refetchInterval: 15_000 });
  const logins = useQuery({ queryKey: ["logins"], queryFn: () => unwrap(api.GET("/server/logins")), retry: false });
  const revoke = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/server/sessions/{id}", { params: { path: { id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["all-sessions"] }),
  });
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("server.sessionsTitle")}</h1>
      <ErrorAlert error={revoke.error} />
      <Card className="overflow-x-auto p-0">
        <div className="px-4 pt-4"><CardTitle>{t("server.activeSessions")}</CardTitle></div>
        {sessions.isPending ? <Spinner /> : !sessions.data ? <ErrorAlert error={sessions.error} /> : (
          <table className="w-full text-left text-sm">
            <thead className={head}><tr>{["server.user", "security.sessions.ip", "security.sessions.device", "security.sessions.lastSeen", ""].map((k) => <th key={k} className={th}>{k && t(k)}</th>)}</tr></thead>
            <tbody>
              {sessions.data.items.map((x) => (
                <tr key={x.id} className={`${row} align-top`}>
                  <td className="px-4 py-3"><span className="font-medium">{x.username}</span> <span className="text-xs text-slate-500">{x.role}</span>
                    {x.impersonated && <span className="ml-1 text-xs text-amber-700 dark:text-amber-400">{t("server.impersonated")}</span>}
                    {x.current && <span className="ml-1 text-xs text-slate-500">{t("server.thisSession")}</span>}
                    {!x.mfa_passed && <span className="ml-1 text-xs text-slate-500">{t("server.mfaPending")}</span>}</td>
                  <td className="px-4 py-3">{x.ip}</td>
                  <td className="max-w-xs break-words px-4 py-3 text-xs">{x.user_agent}</td>
                  <td className="whitespace-nowrap px-4 py-3 text-xs">{new Date(x.last_seen_at).toLocaleString()}</td>
                  <td className="px-4 py-3 text-right"><Button variant="ghost" disabled={revoke.isPending} onClick={() => window.confirm(t("server.confirmSignOut", { name: x.username })) && revoke.mutate(x.id)}>{t("server.signOut")}</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <Card className="overflow-x-auto p-0">
        <div className="px-4 pt-4"><CardTitle>{t("server.loginHistory")}</CardTitle></div>
        {logins.isPending ? <Spinner /> : !logins.data ? <ErrorAlert error={logins.error} /> : (
          <table className="w-full text-left text-sm">
            <thead className={head}><tr>{["server.when", "server.user", "server.result", "security.sessions.ip", "security.sessions.device"].map((k) => <th key={k} className={th}>{t(k)}</th>)}</tr></thead>
            <tbody>
              {logins.data.items.map((l, i) => (
                <tr key={i} className={`${row} align-top`}>
                  <td className="whitespace-nowrap px-4 py-2 text-xs">{new Date(l.at).toLocaleString()}</td>
                  <td className="px-4 py-2">{l.username || "-"}</td>
                  <td className={`px-4 py-2 ${l.result === "ok" ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"}`}>
                    {l.result === "ok" ? t("server.ok") : t("server.denied")}{l.step === "password" && ` (${t("server.passwordStep")})`}{l.reason && ` · ${l.reason}`}
                  </td>
                  <td className="px-4 py-2">{l.ip}</td>
                  <td className="max-w-xs break-words px-4 py-2 text-xs">{l.user_agent}</td>
                </tr>
              ))}
              {logins.data.items.length === 0 && <tr><td colSpan={5} className="px-4 py-6 text-center text-slate-500">{t("server.noLogins")}</td></tr>}
            </tbody>
          </table>
        )}
      </Card>
      <Alert kind="info">{t("server.sessionsHint")}</Alert>
    </div>
  );
}
