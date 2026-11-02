import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Input, Spinner } from "../components/ui";

type Bandwidth = components["schemas"]["Bandwidth"];
type Bytes = components["schemas"]["Bytes"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

export function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  for (; v >= 1024 && i < units.length - 1; i++) v /= 1024;
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

function shiftMonth(month: string, by: number) {
  const [y = 1970, m = 1] = month.split("-").map(Number);
  const d = new Date(Date.UTC(y, m - 1 + by, 1));
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

/** Usage: bandwidth per domain and month, and the sites' logs (USR-STAT-01, 03). */
export function StatsPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  const id = me.data?.account_id;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("stats.title")}</h1>
      {id ? <><BandwidthCard accountId={id} /><LogsCard accountId={id} /></> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

function split(b: Bytes, t: (k: string) => string) {
  return `${t("stats.web")} ${formatBytes(b.web)} · ${t("stats.mail")} ${formatBytes(b.mail)} · ${t("stats.ftp")} ${formatBytes(b.ftp)}`;
}

export function BandwidthCard({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const [month, setMonth] = useState("");
  const q = useQuery({
    queryKey: ["bandwidth", accountId, month],
    queryFn: () => unwrap(api.GET("/accounts/{id}/stats/bandwidth", { params: { path: { id: accountId }, query: month ? { month } : {} } })),
    retry: false,
  });
  if (q.isPending) return <Card><Spinner /></Card>;
  if (!q.data) return <ErrorAlert error={q.error} />;
  const b = q.data;
  const limit = b.limit_mb != null ? b.limit_mb * 1024 * 1024 : null;
  const now = new Date();
  const thisMonth = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
  return (
    <Card>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <CardTitle>{t("stats.bandwidth")}</CardTitle>
        <div className="flex items-center gap-1">
          <Button variant="ghost" aria-label={t("stats.previous")} onClick={() => setMonth(shiftMonth(b.month, -1))}>‹</Button>
          <span className="w-20 text-center font-medium">{b.month}</span>
          <Button variant="ghost" aria-label={t("stats.next")} disabled={b.month >= thisMonth} onClick={() => setMonth(shiftMonth(b.month, 1))}>›</Button>
        </div>
      </div>
      <div className="mb-1 text-3xl font-semibold">{formatBytes(b.total.total)}</div>
      <p className="mb-3 text-sm text-slate-500">
        {limit == null ? t("stats.noLimit") : t("stats.ofLimit", { limit: formatBytes(limit) })} · {split(b.total, t)}
      </p>
      {limit != null && (
        <meter className="mb-4 h-2 w-full" min={0} max={limit} value={b.total.total} high={limit * 0.8} optimum={0} aria-label={t("stats.bandwidth")} />
      )}
      <DayChart b={b} />
      <table className="mt-4 w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["stats.domain", "stats.web", "stats.mail", "stats.ftp", "stats.total"].map((k) => <th key={k} className="py-2 pr-4 font-medium">{t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {b.domains.map((d) => (
            <tr key={d.domain} className="border-t border-slate-100 dark:border-slate-800">
              <td className="py-2 pr-4 font-medium">{d.domain}</td>
              <td className="py-2 pr-4">{formatBytes(d.web)}</td>
              <td className="py-2 pr-4">{formatBytes(d.mail)}</td>
              <td className="py-2 pr-4">{formatBytes(d.ftp)}</td>
              <td className="py-2 pr-4">{formatBytes(d.total)}</td>
            </tr>
          ))}
          {b.domains.length === 0 && <tr><td colSpan={5} className="py-4 text-center text-slate-500">{t("stats.nothingYet")}</td></tr>}
        </tbody>
      </table>
      <p className="mt-2 text-xs text-slate-500">{t("stats.hint")}</p>
    </Card>
  );
}

/** One bar per day, the day's total; hover shows the split. */
function DayChart({ b }: { b: Bandwidth }) {
  const { t } = useTranslation();
  const max = Math.max(1, ...b.days.map((d) => d.total));
  // Every day of the month has its slot, so a bar is as wide on the 2nd as on the 30th.
  const [y = 1970, m = 1] = b.month.split("-").map(Number);
  const slots = new Date(Date.UTC(y, m, 0)).getUTCDate();
  return (
    <div role="img" aria-label={t("stats.perDay")} className="flex h-32 items-end gap-0.5 border-b border-slate-200 dark:border-slate-700">
      {Array.from({ length: slots }, (_, i) => b.days[i]).map((d, i) => d ? (
        <div key={d.day} data-day={d.day} className="group relative flex h-full flex-1 items-end" title={`${d.day}: ${formatBytes(d.total)} (${split(d, t)})`}>
          <div className="w-full rounded-t bg-blue-600 group-hover:bg-blue-800 dark:bg-blue-400 dark:group-hover:bg-blue-300"
            style={{ height: d.total ? `max(2px, ${(d.total / max) * 100}%)` : 0 }} />
        </div>
      ) : <div key={i} className="h-full flex-1" />)}
    </div>
  );
}

export function LogsCard({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const [kind, setKind] = useState<"access" | "error">("access");
  const [lines, setLines] = useState(100);
  const [filter, setFilter] = useState("");
  const [search, setSearch] = useState("");
  const q = useQuery({
    queryKey: ["logs", accountId, kind, lines, search],
    queryFn: () => unwrap(api.GET("/accounts/{id}/logs/{kind}", { params: { path: { id: accountId, kind }, query: { lines, q: search || undefined } } })),
    retry: false,
  });
  return (
    <Card>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <CardTitle>{t("stats.logs")}</CardTitle>
        <a className="text-sm text-blue-700 hover:underline dark:text-blue-400" href={`/api/v1/accounts/${accountId}/logs/${kind}/download`}>{t("stats.download")}</a>
      </div>
      <form onSubmit={(e) => { e.preventDefault(); setSearch(filter); }} className="mb-3 flex flex-wrap items-center gap-2 text-sm">
        <div className="flex rounded-md border border-slate-300 dark:border-slate-700" role="tablist">
          {(["access", "error"] as const).map((k) => (
            <button key={k} type="button" role="tab" aria-selected={kind === k}
              className={`px-3 py-1.5 ${kind === k ? "bg-slate-200 font-medium dark:bg-slate-800" : ""}`} onClick={() => setKind(k)}>{t(`stats.${k}Log`)}</button>
          ))}
        </div>
        <select aria-label={t("stats.lines")} className={selectClass} value={lines} onChange={(e) => setLines(Number(e.target.value))}>
          {[50, 100, 500, 1000].map((n) => <option key={n} value={n}>{t("stats.lastLines", { n })}</option>)}
        </select>
        <Input aria-label={t("stats.search")} className="max-w-xs" placeholder={t("stats.search")} value={filter} onChange={(e) => setFilter(e.target.value)} />
        <Button type="submit" variant="secondary">{t("stats.show")}</Button>
        <Button type="button" variant="ghost" onClick={() => void q.refetch()}>{t("stats.refresh")}</Button>
      </form>
      <ErrorAlert error={q.error} />
      {q.isPending ? <Spinner /> : (
        <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-3 font-mono text-xs dark:bg-slate-950">
          {q.data?.lines.length ? q.data.lines.join("\n") : t("stats.noLines")}
        </pre>
      )}
    </Card>
  );
}
