import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { formatBytes } from "./StatsPage";

type Backup = components["schemas"]["Backup"];
type Schedule = components["schemas"]["BackupSchedule"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

/** Backups: the account's own for users, the schedule for admins (USR-BAK-01, ADM-BAK-01). */
export function BackupsPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("backups.title")}</h1>
      {me.data?.role === "admin" ? <><ScheduleCard /><RemovedAccounts /></>
        : me.data?.account_id ? <AccountBackups accountId={me.data.account_id} /> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

export function AccountBackups({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const key = ["backups", accountId];
  const q = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/accounts/{id}/backups", { params: { path: { id: accountId } } })),
    retry: false,
    // A running backup finishes by itself.
    refetchInterval: (query) => (query.state.data?.backups.some((b) => b.status === "running") ? 3000 : false),
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: key });
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/backups", { params: { path: { id: accountId } } })),
    onSuccess: refresh,
  });
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  const o = q.data;
  return (
    <div className="space-y-6">
      <p className="max-w-2xl text-sm text-slate-600 dark:text-slate-400">{t("backups.intro", { max: o.max_manual })}</p>
      <Card>
        <div className="flex flex-wrap items-center gap-3">
          <Button disabled={create.isPending || o.backups.some((b) => b.status === "running")} onClick={() => create.mutate()}>{t("backups.create")}</Button>
          {o.schedule.enabled && <span className="text-sm text-slate-500">{t("backups.scheduledNote", { hour: o.schedule.hour, keep: o.schedule.keep })}</span>}
        </div>
        <div className="mt-3"><ErrorAlert error={create.error} /></div>
      </Card>
      <Card className="overflow-x-auto p-0">
        <div className="px-4 pt-4"><CardTitle>{t("backups.list")}</CardTitle></div>
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
            <tr>{["backups.when", "backups.kind", "backups.size", "backups.status", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
          </thead>
          <tbody>
            {o.backups.map((b) => <Row key={b.id} b={b} onChanged={refresh} />)}
            {o.backups.length === 0 && <tr><td colSpan={5} className="px-4 py-6 text-center text-slate-500">{t("backups.none")}</td></tr>}
          </tbody>
        </table>
      </Card>
      <p className="text-xs text-slate-500">{t("backups.hint")}</p>
    </div>
  );
}

function Row({ b, onChanged }: { b: Backup; onChanged: () => void }) {
  const { t } = useTranslation();
  const remove = useMutation({ mutationFn: () => unwrap(api.DELETE("/backups/{id}", { params: { path: { id: b.id } } })), onSuccess: onChanged });
  const ok = b.status === "ok";
  return (
    <>
      <tr className="border-t border-slate-100 align-top dark:border-slate-800">
        <td className="whitespace-nowrap px-4 py-3">{new Date(b.created_at).toLocaleString()}</td>
        <td className="px-4 py-3">{t(`backups.${b.kind}`)}</td>
        <td className="px-4 py-3">{ok ? formatBytes(b.size) : "-"}</td>
        <td className="px-4 py-3">
          <span className={b.status === "failed" ? "text-red-700 dark:text-red-400" : ok ? "text-green-700 dark:text-green-400" : "text-slate-500"}>{t(`backups.${b.status}`)}</span>
          {b.detail && <div className="max-w-md break-words text-xs text-slate-500">{b.detail}</div>}
        </td>
        <td className="whitespace-nowrap px-4 py-3 text-right">
          {ok && <a className="mr-3 text-blue-700 hover:underline dark:text-blue-400" href={`/api/v1/backups/${b.id}/download`}>{t("backups.download")}</a>}
          <Button variant="ghost" disabled={remove.isPending || b.status === "running"}
            onClick={() => window.confirm(t("backups.confirmDelete")) && remove.mutate()}>{t("common.delete")}</Button>
        </td>
      </tr>
      {remove.error && <tr><td colSpan={5} className="px-4 pb-3"><ErrorAlert error={remove.error} /></td></tr>}
    </>
  );
}

const days = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"] as const;

/** The backup schedule for admins (ADM-BAK-01). */
function ScheduleCard() {
  const q = useQuery({ queryKey: ["backup-schedule"], queryFn: () => unwrap(api.GET("/server/backups/schedule")), retry: false });
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  return <ScheduleForm initial={q.data} />;
}

function ScheduleForm({ initial }: { initial: Schedule }) {
  const { t } = useTranslation();
  const [s, setS] = useState<Schedule>(initial);
  const save = useMutation({ mutationFn: () => unwrap(api.PUT("/server/backups/schedule", { body: s })), onSuccess: (r) => setS(r) });
  const num = (k: "hour" | "day" | "keep") => (e: React.ChangeEvent<HTMLInputElement>) => setS({ ...s, [k]: Number(e.target.value) });
  return (
    <Card>
      <CardTitle>{t("backups.schedule")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("backups.scheduleHint")}</p>
      <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-4">
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={s.enabled} onChange={(e) => setS({ ...s, enabled: e.target.checked })} /> {t("backups.enabled")}</label>
        <div className="flex flex-wrap items-end gap-4">
          <Field id="bk-freq" label={t("backups.frequency")}>
            <select id="bk-freq" className={selectClass} value={s.frequency} onChange={(e) => setS({ ...s, frequency: e.target.value as Schedule["frequency"] })}>
              {(["daily", "weekly", "monthly"] as const).map((f) => <option key={f} value={f}>{t(`backups.${f}`)}</option>)}
            </select>
          </Field>
          {s.frequency === "weekly" && (
            <Field id="bk-weekday" label={t("backups.weekday")}>
              <select id="bk-weekday" className={selectClass} value={s.weekday} onChange={(e) => setS({ ...s, weekday: Number(e.target.value) })}>
                {days.map((d, i) => <option key={d} value={i}>{t(`backups.${d}`)}</option>)}
              </select>
            </Field>
          )}
          {s.frequency === "monthly" && (
            <Field id="bk-day" label={t("backups.day")}><Input id="bk-day" type="number" min={1} max={28} value={s.day} onChange={num("day")} /></Field>
          )}
          <Field id="bk-hour" label={t("backups.hour")}><Input id="bk-hour" type="number" min={0} max={23} value={s.hour} onChange={num("hour")} /></Field>
          <Field id="bk-keep" label={t("backups.keep")}><Input id="bk-keep" type="number" min={1} max={90} value={s.keep} onChange={num("keep")} /></Field>
        </div>
        <ErrorAlert error={save.error} />
        {save.isSuccess && <Alert kind="success">{t("common.saved")}</Alert>}
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
      </form>
    </Card>
  );
}

type Orphan = components["schemas"]["OrphanBackup"];

/** Backups of removed accounts: restore one into a new account, or delete it. */
function RemovedAccounts() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["orphan-backups"], queryFn: () => unwrap(api.GET("/server/backups")), retry: false });
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  return (
    <Card className="overflow-x-auto p-0">
      <div className="px-4 pt-4"><CardTitle>{t("backups.removed")}</CardTitle></div>
      <p className="px-4 pb-2 text-sm text-slate-500">{t("backups.removedHint")}</p>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["backups.account", "backups.when", "backups.size", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {q.data.items.map((o) => <RemovedRow key={o.id} o={o} />)}
          {q.data.items.length === 0 && <tr><td colSpan={4} className="px-4 py-6 text-center text-slate-500">{t("backups.noneRemoved")}</td></tr>}
        </tbody>
      </table>
    </Card>
  );
}

function RemovedRow({ o }: { o: Orphan }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const done = () => void qc.invalidateQueries({ queryKey: ["orphan-backups"] });
  const restore = useMutation({
    mutationFn: () => unwrap(api.POST("/server/backups/{id}/restore", { params: { path: { id: o.id } }, body: {} })),
    onSuccess: (r) => setJobId(r.job_id),
  });
  const remove = useMutation({ mutationFn: () => unwrap(api.DELETE("/backups/{id}", { params: { path: { id: o.id } } })), onSuccess: done });
  return (
    <>
      <tr className="border-t border-slate-100 align-top dark:border-slate-800">
        <td className="px-4 py-3 font-medium">{o.username}</td>
        <td className="whitespace-nowrap px-4 py-3">{new Date(o.created_at).toLocaleString()}</td>
        <td className="px-4 py-3">{formatBytes(o.size)}</td>
        <td className="whitespace-nowrap px-4 py-3 text-right">
          <a className="mr-3 text-blue-700 hover:underline dark:text-blue-400" href={`/api/v1/backups/${o.id}/download`}>{t("backups.download")}</a>
          <Button variant="ghost" disabled={restore.isPending || !!jobId} onClick={() => window.confirm(t("backups.confirmRestore", { name: o.username })) && restore.mutate()}>{t("backups.restore")}</Button>
          <Button variant="ghost" disabled={remove.isPending} onClick={() => window.confirm(t("backups.confirmDelete")) && remove.mutate()}>{t("common.delete")}</Button>
        </td>
      </tr>
      {(restore.error || remove.error || jobId) && (
        <tr><td colSpan={4} className="space-y-2 px-4 pb-3">
          <ErrorAlert error={restore.error ?? remove.error} />
          {jobId && <JobNotice jobId={jobId} onDone={done} />}
        </td></tr>
      )}
    </>
  );
}
