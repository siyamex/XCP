import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";

type Overview = components["schemas"]["CronOverview"];
type CronJob = components["schemas"]["CronJob"];
type Form = { schedule: string; command: string; email: string; enabled: boolean };

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

/** Schedule presets for the helper; "" is a custom schedule. */
const presets = [
  ["*/5 * * * *", "cron.every5"],
  ["*/15 * * * *", "cron.every15"],
  ["0 * * * *", "cron.hourly"],
  ["0 3 * * *", "cron.daily"],
  ["0 3 * * 0", "cron.weekly"],
  ["0 3 1 * *", "cron.monthly"],
  ["* * * * *", "cron.everyMinute"],
] as const;

const fieldNames = ["minute", "hour", "day", "month", "weekday"] as const;

/** Cron jobs: the account's scheduled commands (USR-ADV-01). */
export function CronPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("cron.title")}</h1>
      {me.data?.account_id ? <AccountCron accountId={me.data.account_id} /> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

function when(iso: string) {
  return new Date(iso).toLocaleString();
}

/** One account's cron jobs. */
export function AccountCron({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const key = ["cron", accountId];
  const overview = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/accounts/{id}/cron", { params: { path: { id: accountId } } })),
    retry: false,
    refetchInterval: 30_000, // last runs change by themselves
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: key });
  const started = (r: { job_id?: string }) => {
    setJobId(r.job_id);
    refresh();
  };
  if (overview.isPending) return <Spinner />;
  if (!overview.data) return <ErrorAlert error={overview.error} />;
  const o = overview.data;
  return (
    <div className="space-y-6">
      <p className="max-w-2xl text-sm text-slate-600 dark:text-slate-400">{t("cron.intro", { zone: o.time_zone })}</p>
      {o.status_error && <Alert kind="info">{o.status_error}</Alert>}
      <JobNotice jobId={jobId} onDone={refresh} />
      <Card>
        <CardTitle>{t("cron.add")}</CardTitle>
        <JobForm accountId={accountId} o={o} onStarted={started} />
      </Card>
      <Card className="overflow-x-auto p-0">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
          <CardTitle>{t("cron.jobs")}</CardTitle>
          <span className="text-xs text-slate-500">
            {o.max_jobs == null ? t("databases.used", { used: o.jobs.length }) : t("databases.usedOf", { used: o.jobs.length, max: o.max_jobs })}
          </span>
        </div>
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
            <tr>{["cron.schedule", "cron.command", "cron.nextRun", "cron.lastRun", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
          </thead>
          <tbody>
            {o.jobs.map((j) => <JobRow key={j.id} j={j} accountId={accountId} o={o} onStarted={started} />)}
            {o.jobs.length === 0 && <tr><td colSpan={5} className="px-4 py-6 text-center text-slate-500">{t("cron.noJobs")}</td></tr>}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

/** The schedule helper: presets, or the five fields. */
function ScheduleInput({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation();
  const preset = presets.find(([s]) => s === value)?.[0] ?? "";
  const fields = value.split(" ");
  const parts = fields.length === 5 ? fields : ["*", "*", "*", "*", "*"];
  const setPart = (i: number, v: string) => onChange(parts.map((p, j) => (j === i ? v.replace(/\s/g, "") || "*" : p)).join(" "));
  return (
    <div className="space-y-2">
      <select id={id} aria-label={t("cron.preset")} className={selectClass} value={preset} onChange={(e) => e.target.value && onChange(e.target.value)}>
        {presets.map(([s, k]) => <option key={s} value={s}>{t(k)}</option>)}
        <option value="">{t("cron.custom")}</option>
      </select>
      <div className="grid grid-cols-5 gap-1">
        {fieldNames.map((n, i) => (
          <label key={n} className="text-xs text-slate-500">
            {t(`cron.${n}`)}
            <Input className="font-mono" value={parts[i]} onChange={(e) => setPart(i, e.target.value)} />
          </label>
        ))}
      </div>
    </div>
  );
}

function JobForm({ accountId, o, job, onStarted, onDone }: {
  accountId: string; o: Overview; job?: CronJob; onStarted: (r: { job_id?: string }) => void; onDone?: () => void;
}) {
  const { t } = useTranslation();
  const empty: Form = { schedule: "0 3 * * *", command: "", email: o.default_email, enabled: true };
  const [form, setForm] = useState<Form>(job ? { schedule: job.schedule, command: job.command, email: job.email, enabled: job.enabled } : empty);
  const save = useMutation({
    mutationFn: () => job
      ? unwrap(api.PUT("/cron/{id}", { params: { path: { id: job.id } }, body: form }))
      : unwrap(api.POST("/accounts/{id}/cron", { params: { path: { id: accountId } }, body: form })),
    onSuccess: (r) => {
      if (!job) setForm(empty);
      onStarted(r);
      onDone?.();
    },
  });
  const p = job?.id ?? "new";
  return (
    <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-3">
      <div className="grid gap-4 lg:grid-cols-2">
        <Field id={`sched-${p}`} label={t("cron.schedule")}>
          <ScheduleInput id={`sched-${p}`} value={form.schedule} onChange={(schedule) => setForm({ ...form, schedule })} />
        </Field>
        <div className="space-y-3">
          <Field id={`cmd-${p}`} label={t("cron.command")}>
            <Input id={`cmd-${p}`} className="font-mono" required placeholder="php ~/public_html/cron.php" value={form.command}
              onChange={(e) => setForm({ ...form, command: e.target.value })} />
          </Field>
          <Field id={`mail-${p}`} label={t("cron.email")}>
            <Input id={`mail-${p}`} type="email" placeholder={t("cron.emailPlaceholder")} value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> {t("cron.enabled")}
          </label>
        </div>
      </div>
      <p className="text-xs text-slate-500">{t("cron.commandHint")}</p>
      <ErrorAlert error={save.error} />
      <Button type="submit" disabled={save.isPending}>{job ? t("common.save") : t("cron.addButton")}</Button>
    </form>
  );
}

function LastRun({ j }: { j: CronJob }) {
  const { t } = useTranslation();
  const r = j.last_run;
  if (!r) return <span className="text-slate-500">{t("cron.never")}</span>;
  if (r.skipped) return <span className="text-amber-700 dark:text-amber-400">{when(r.start)}: {r.skipped}</span>;
  const ok = r.exit_code === 0;
  return (
    <span className={ok ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"}>
      {when(r.start)} · {ok ? t("cron.ok") : t("cron.exitCode", { code: r.exit_code })} · {(r.duration_ms / 1000).toFixed(1)} s
    </span>
  );
}

function JobRow({ j, accountId, o, onStarted }: { j: CronJob; accountId: string; o: Overview; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState<"" | "edit" | "output">("");
  const remove = useMutation({ mutationFn: () => unwrap(api.DELETE("/cron/{id}", { params: { path: { id: j.id } } })), onSuccess: onStarted });
  return (
    <>
      <tr className="border-t border-slate-100 align-top dark:border-slate-800">
        <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{j.schedule}{!j.enabled && <span className="ml-2 font-sans text-slate-500">({t("cron.off")})</span>}</td>
        <td className="max-w-xs break-all px-4 py-3 font-mono text-xs">{j.command}</td>
        <td className="whitespace-nowrap px-4 py-3 text-xs">{j.next_runs[0] ? when(j.next_runs[0]) : "-"}</td>
        <td className="px-4 py-3 text-xs"><LastRun j={j} /></td>
        <td className="whitespace-nowrap px-4 py-3 text-right">
          {j.last_run?.output && <Button variant="ghost" onClick={() => setOpen(open === "output" ? "" : "output")}>{t("cron.output")}</Button>}
          <Button variant="ghost" onClick={() => setOpen(open === "edit" ? "" : "edit")}>{open === "edit" ? t("common.cancel") : t("cron.edit")}</Button>
          <Button variant="ghost" disabled={remove.isPending}
            onClick={() => window.confirm(t("cron.confirmDelete", { command: j.command })) && remove.mutate()}>{t("common.delete")}</Button>
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50 dark:bg-slate-900/50">
          <td colSpan={5} className="space-y-3 px-4 py-4">
            <ErrorAlert error={remove.error} />
            {open === "output"
              ? <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded bg-white p-3 font-mono text-xs dark:bg-slate-950">{j.last_run?.output}</pre>
              : <JobForm accountId={accountId} o={o} job={j} onStarted={onStarted} onDone={() => setOpen("")} />}
          </td>
        </tr>
      )}
    </>
  );
}
