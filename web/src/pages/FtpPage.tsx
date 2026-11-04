import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { FtpSessionsCard } from "./FtpSessionsCard";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { generatePassword } from "../lib/password";

type Overview = components["schemas"]["FTPOverview"];
type Login = components["schemas"]["FTPAccount"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

/** FTP: the account's FTP logins (USR-FTP-01). */
export function FtpPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("ftp.title")}</h1>
      {me.data?.account_id ? <AccountFtp accountId={me.data.account_id} /> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

function folderLabel(folder: string, t: (k: string) => string) {
  return folder === "." ? t("ftp.wholeHome") : `~/${folder}`;
}

/** One account's FTP logins. */
export function AccountFtp({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const key = ["ftp", accountId];
  const overview = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/accounts/{id}/ftp", { params: { path: { id: accountId } } })),
    retry: false,
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
      <p className="max-w-2xl text-sm text-slate-600 dark:text-slate-400">{t("ftp.intro")}</p>
      <JobNotice jobId={jobId} onDone={refresh} />
      <ConnectCard o={o} />
      <FtpSessionsCard accountId={accountId} />
      <CreateCard accountId={accountId} o={o} onStarted={started} />
      <Card className="overflow-x-auto p-0">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
          <CardTitle>{t("ftp.logins")}</CardTitle>
          <span className="text-xs text-slate-500">
            {o.max_logins == null ? t("databases.used", { used: o.logins.length }) : t("databases.usedOf", { used: o.logins.length, max: o.max_logins })}
          </span>
        </div>
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
            <tr>{["ftp.login", "ftp.folder", "ftp.quota", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
          </thead>
          <tbody>
            {o.logins.map((l) => <LoginRow key={l.id} l={l} onStarted={started} />)}
            {o.logins.length === 0 && <tr><td colSpan={4} className="px-4 py-6 text-center text-slate-500">{t("ftp.noLogins")}</td></tr>}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function ConnectCard({ o }: { o: Overview }) {
  const { t } = useTranslation();
  return (
    <Card>
      <CardTitle>{t("ftp.connect")}</CardTitle>
      <dl className="grid gap-2 text-sm sm:grid-cols-[12rem_1fr]">
        <dt className="text-slate-500">{t("ftp.server")}</dt><dd className="font-mono">{o.server || "-"}</dd>
        <dt className="text-slate-500">{t("ftp.port")}</dt><dd className="font-mono">{o.port}</dd>
        <dt className="text-slate-500">{t("ftp.security")}</dt><dd>{t("ftp.securityHint")}</dd>
      </dl>
    </Card>
  );
}

function CreateCard({ accountId, o, onStarted }: { accountId: string; o: Overview; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const empty = { domain_id: o.domains[0]?.id ?? "", name: "", password: "", folder: "", quota_mb: 0 };
  const [form, setForm] = useState(empty);
  const [shown, setShown] = useState<{ login: string; password: string }>();
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/ftp", { params: { path: { id: accountId } }, body: form })),
    onSuccess: (r) => {
      setShown({ login: r.login, password: form.password });
      setForm({ ...empty, domain_id: form.domain_id });
      onStarted(r);
    },
  });
  return (
    <Card>
      <CardTitle>{t("ftp.create")}</CardTitle>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="grid items-end gap-3 md:grid-cols-2 lg:grid-cols-3">
        <Field id="ftp-name" label={t("ftp.login")}>
          <div className="flex items-center gap-1 text-sm">
            <Input id="ftp-name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <span className="text-slate-500">@</span>
            <select aria-label={t("ftp.domain")} className={selectClass} value={form.domain_id} onChange={(e) => setForm({ ...form, domain_id: e.target.value })}>
              {o.domains.map((d) => <option key={d.id} value={d.id}>{d.display_name}</option>)}
            </select>
          </div>
        </Field>
        <Field id="ftp-pw" label={t("databases.password")}>
          <div className="flex gap-1">
            <Input id="ftp-pw" required autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <Button type="button" variant="ghost" onClick={() => setForm({ ...form, password: generatePassword() })}>{t("databases.generate")}</Button>
          </div>
        </Field>
        <Field id="ftp-folder" label={t("ftp.folder")}>
          <div className="flex items-center gap-1 text-sm"><span className="text-slate-500">~/</span>
            <Input id="ftp-folder" placeholder={t("ftp.folderPlaceholder")} value={form.folder} onChange={(e) => setForm({ ...form, folder: e.target.value })} /></div>
        </Field>
        <Field id="ftp-quota" label={t("ftp.quotaMB")}>
          <Input id="ftp-quota" type="number" min={0} value={form.quota_mb} onChange={(e) => setForm({ ...form, quota_mb: Number(e.target.value) })} />
        </Field>
        <Button type="submit" disabled={create.isPending || o.domains.length === 0}>{t("ftp.createButton")}</Button>
      </form>
      <p className="mt-2 text-xs text-slate-500">{t("ftp.folderHint")}</p>
      <div className="mt-3"><ErrorAlert error={create.error} /></div>
      {shown && (
        <div className="mt-3 rounded-md bg-slate-50 p-3 font-mono text-sm dark:bg-slate-900">
          <p className="mb-1 font-sans text-xs text-slate-500">{t("ftp.shownOnce")}</p>
          <div>{t("ftp.server")}: {o.server}</div><div>{t("ftp.login")}: {shown.login}</div><div>{t("databases.password")}: {shown.password}</div>
        </div>
      )}
    </Card>
  );
}

function LoginRow({ l, onStarted }: { l: Login; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ folder: l.folder === "." ? "" : l.folder, quota_mb: l.quota_mb });
  const [password, setPassword] = useState("");
  const path = { params: { path: { id: l.id } } };
  const update = useMutation({
    mutationFn: () => unwrap(api.PUT("/ftp/{id}", { ...path, body: form })),
    onSuccess: (r) => { setOpen(false); onStarted(r); },
  });
  const setPw = useMutation({
    mutationFn: () => unwrap(api.PUT("/ftp/{id}/password", { ...path, body: { password } })),
    onSuccess: (r) => { setPassword(""); onStarted(r); },
  });
  const remove = useMutation({ mutationFn: () => unwrap(api.DELETE("/ftp/{id}", path)), onSuccess: onStarted });
  return (
    <>
      <tr className="border-t border-slate-100 align-top dark:border-slate-800">
        <td className="px-4 py-3 font-medium">{l.login}</td>
        <td className="px-4 py-3 font-mono text-xs">{folderLabel(l.folder, t)}</td>
        <td className="px-4 py-3">{l.quota_mb ? `${l.quota_mb} MB` : <span className="text-slate-500">{t("ftp.noQuota")}</span>}</td>
        <td className="whitespace-nowrap px-4 py-3 text-right">
          <Button variant="ghost" onClick={() => setOpen(!open)}>{open ? t("common.cancel") : t("databases.manage")}</Button>
          <Button variant="ghost" disabled={remove.isPending}
            onClick={() => window.confirm(t("ftp.confirmDelete", { login: l.login })) && remove.mutate()}>{t("common.delete")}</Button>
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50 dark:bg-slate-900/50">
          <td colSpan={4} className="space-y-4 px-4 py-4">
            <ErrorAlert error={update.error ?? setPw.error ?? remove.error} />
            <form onSubmit={(e) => { e.preventDefault(); update.mutate(); }} className="flex flex-wrap items-end gap-2">
              <Field id={`folder-${l.id}`} label={t("ftp.folder")}>
                <Input id={`folder-${l.id}`} placeholder={t("ftp.folderPlaceholder")} value={form.folder} onChange={(e) => setForm({ ...form, folder: e.target.value })} />
              </Field>
              <Field id={`quota-${l.id}`} label={t("ftp.quotaMB")}>
                <Input id={`quota-${l.id}`} type="number" min={0} value={form.quota_mb} onChange={(e) => setForm({ ...form, quota_mb: Number(e.target.value) })} />
              </Field>
              <Button type="submit" variant="secondary" disabled={update.isPending}>{t("common.save")}</Button>
            </form>
            <form onSubmit={(e) => { e.preventDefault(); setPw.mutate(); }} className="flex flex-wrap items-end gap-2">
              <Field id={`pw-${l.id}`} label={t("databases.newPassword")}>
                <Input id={`pw-${l.id}`} required autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              </Field>
              <Button type="button" variant="ghost" onClick={() => setPassword(generatePassword())}>{t("databases.generate")}</Button>
              <Button type="submit" variant="secondary" disabled={setPw.isPending}>{t("databases.changePassword")}</Button>
            </form>
          </td>
        </tr>
      )}
    </>
  );
}
