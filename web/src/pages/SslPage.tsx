import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { cn } from "../lib/cn";

type DomainSSL = components["schemas"]["DomainSSL"];
type Cert = components["schemas"]["Certificate"];
type SettingsInput = components["schemas"]["SSLSettingsInput"];

const selectClass = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";
const textareaClass = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900";

const statusStyle: Record<string, string> = {
  ok: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200",
  failed: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200",
  skipped: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
  "": "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
};

/** Days left, colored when a certificate expires soon. */
function Expiry({ cert }: { cert: Cert }) {
  const { t } = useTranslation();
  return (
    <span className={cn(cert.days_left < 14 && "font-semibold text-red-700 dark:text-red-400", cert.days_left >= 14 && cert.days_left < 30 && "text-amber-700 dark:text-amber-400")}>
      {new Date(cert.not_after).toLocaleDateString()} ({t("ssl.daysLeft", { count: cert.days_left })})
    </span>
  );
}

/** SSL/TLS: settings and the expiry dashboard for admins, the account's domains for users. */
export function SslPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("ssl.title")}</h1>
      {me.data?.role === "admin" ? <>
        <SettingsCard />
        <CertificateList />
      </> : me.data?.account_id ? <AccountSSL accountId={me.data.account_id} /> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

/** The SSL state of one account's domains: on the account page and the user's SSL page. */
export function AccountSSL({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const [open, setOpen] = useState<string>();
  const path = { params: { path: { id: accountId } } };
  const list = useQuery({ queryKey: ["account-ssl", accountId], queryFn: () => unwrap(api.GET("/accounts/{id}/ssl", path)), retry: false });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["account-ssl", accountId] });
  const started = (r: { job_id?: string }) => {
    setJobId(r.job_id);
    refresh();
  };
  const run = useMutation({ mutationFn: () => unwrap(api.POST("/accounts/{id}/ssl/run", path)), onSuccess: started });

  if (list.isPending) return <Spinner />;
  if (!list.data) return <ErrorAlert error={list.error} />;
  return (
    <Card className="overflow-x-auto p-0">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
        <CardTitle>{t("ssl.domains")}</CardTitle>
        <Button variant="secondary" disabled={run.isPending} onClick={() => run.mutate()}>{t("ssl.runNow")}</Button>
      </div>
      <div className="space-y-2 px-4">
        <JobNotice jobId={jobId} onDone={refresh} />
        <ErrorAlert error={run.error} />
      </div>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["ssl.domain", "ssl.status", "ssl.certificate", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {list.data.items.map((d) => (
            <DomainRow key={d.domain_id} d={d} open={open === d.domain_id} onToggle={() => setOpen(open === d.domain_id ? undefined : d.domain_id)} onStarted={started} />
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function DomainRow({ d, open, onToggle, onStarted }: { d: DomainSSL; open: boolean; onToggle: () => void; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const path = { params: { path: { id: d.domain_id } } };
  const options = useMutation({
    mutationFn: (o: { autossl: boolean; force_https: boolean }) => unwrap(api.PUT("/domains/{id}/ssl", { ...path, body: o })),
    onSuccess: onStarted,
  });
  const remove = useMutation({ mutationFn: () => unwrap(api.DELETE("/domains/{id}/certificate", path)), onSuccess: onStarted });
  return (
    <>
      <tr className="border-t border-slate-100 align-top dark:border-slate-800">
        <td className="px-4 py-3 font-medium">{d.display_name}</td>
        <td className="px-4 py-3">
          <span className={cn("rounded px-2 py-0.5 text-xs font-medium", statusStyle[d.status] ?? statusStyle[""])}>{t(`ssl.statuses.${d.status || "none"}`)}</span>
          {d.detail && <p className="mt-1 max-w-sm text-xs text-slate-500">{d.detail}</p>}
        </td>
        <td className="px-4 py-3">
          {d.certificate ? <>
            <div><Expiry cert={d.certificate} /></div>
            <div className="text-xs text-slate-500">{t(`ssl.sources.${d.certificate.source}`)} · {d.certificate.issuer}</div>
          </> : <span className="text-slate-500">{t("ssl.none")}</span>}
        </td>
        <td className="whitespace-nowrap px-4 py-3 text-right"><Button variant="ghost" onClick={onToggle}>{open ? t("common.cancel") : t("ssl.manage")}</Button></td>
      </tr>
      {open && (
        <tr className="bg-slate-50 dark:bg-slate-900/50">
          <td colSpan={4} className="space-y-4 px-4 py-4">
            <ErrorAlert error={options.error ?? remove.error} />
            <div className="flex flex-wrap gap-6 text-sm">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={d.autossl} disabled={options.isPending} onChange={(e) => options.mutate({ autossl: e.target.checked, force_https: d.force_https })} />
                {t("ssl.autossl")}
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={d.force_https} disabled={options.isPending || !d.certificate} onChange={(e) => options.mutate({ autossl: d.autossl, force_https: e.target.checked })} />
                {t("ssl.forceHttps")}
              </label>
            </div>
            <UploadForm domainId={d.domain_id} onStarted={onStarted} />
            {d.certificate && <Button variant="danger" disabled={remove.isPending} onClick={() => window.confirm(t("ssl.confirmRemove", { name: d.display_name })) && remove.mutate()}>{t("ssl.remove")}</Button>}
          </td>
        </tr>
      )}
    </>
  );
}

function UploadForm({ domainId, onStarted }: { domainId: string; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [form, setForm] = useState({ certificate: "", chain: "", key: "" });
  const upload = useMutation({
    mutationFn: () => unwrap(api.PUT("/domains/{id}/certificate", { params: { path: { id: domainId } }, body: form })),
    onSuccess: (r) => {
      setForm({ certificate: "", chain: "", key: "" });
      onStarted(r);
    },
  });
  return (
    <form onSubmit={(e) => { e.preventDefault(); upload.mutate(); }} className="space-y-3">
      <p className="text-sm font-medium">{t("ssl.upload")}</p>
      <div className="grid gap-3 md:grid-cols-3">
        {(["certificate", "chain", "key"] as const).map((k) => (
          <Field key={k} id={`up-${domainId}-${k}`} label={t(`ssl.fields.${k}`)}>
            <textarea id={`up-${domainId}-${k}`} rows={5} className={textareaClass} required={k !== "chain"} value={form[k]}
              placeholder={k === "key" ? "-----BEGIN PRIVATE KEY-----" : "-----BEGIN CERTIFICATE-----"}
              onChange={(e) => setForm({ ...form, [k]: e.target.value })} spellCheck={false} autoComplete="off" />
          </Field>
        ))}
      </div>
      <ErrorAlert error={upload.error} />
      <Button type="submit" variant="secondary" disabled={upload.isPending}>{t("ssl.install")}</Button>
    </form>
  );
}

/** The expiry dashboard (ADM-SSL-05). */
function CertificateList() {
  const { t } = useTranslation();
  const list = useQuery({ queryKey: ["certificates"], queryFn: () => unwrap(api.GET("/ssl/certificates")), retry: false });
  if (list.isPending) return <Spinner />;
  if (!list.data) return <ErrorAlert error={list.error} />;
  const soon = list.data.items.filter((c) => c.days_left < 14).length;
  return (
    <Card className="overflow-x-auto p-0">
      <div className="px-4 pt-4"><CardTitle>{t("ssl.dashboard")}</CardTitle></div>
      {soon > 0 && <div className="px-4"><Alert>{t("ssl.expiringSoon", { count: soon })}</Alert></div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["ssl.names", "ssl.account", "ssl.source", "ssl.expires"].map((k) => <th key={k} className="px-4 py-3 font-medium">{t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {list.data.items.map((c) => (
            <tr key={c.id} className="border-t border-slate-100 dark:border-slate-800">
              <td className="px-4 py-3">{c.names.join(", ")}{!c.domain && <span className="ml-2 rounded bg-brand/10 px-1.5 py-0.5 text-xs text-brand">{t("ssl.server")}</span>}</td>
              <td className="px-4 py-3">{c.account || "-"}</td>
              <td className="px-4 py-3">{t(`ssl.sources.${c.source}`)} · {c.issuer}</td>
              <td className="px-4 py-3"><Expiry cert={c} /></td>
            </tr>
          ))}
          {list.data.items.length === 0 && <tr><td colSpan={4} className="px-4 py-6 text-center text-slate-500">{t("ssl.noCertificates")}</td></tr>}
        </tbody>
      </table>
    </Card>
  );
}

function SettingsCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const current = useQuery({ queryKey: ["ssl-settings"], queryFn: () => unwrap(api.GET("/server/ssl")), retry: false });
  const [form, setForm] = useState<SettingsInput>();
  useEffect(() => {
    if (current.data && !form) {
      const { has_eab_key: _, ...rest } = current.data;
      setForm({ ...rest, eab_key: "" });
    }
  }, [current.data, form]);
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/server/ssl", { body: form! })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["ssl-settings"] }),
  });
  const run = useMutation({ mutationFn: () => unwrap(api.POST("/server/ssl/run")), onSuccess: (r) => setJobId(r.job_id) });
  if (!form) return current.error ? <ErrorAlert error={current.error} /> : <Spinner />;
  const set = (k: keyof SettingsInput) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const custom = form.provider === "custom";

  return (
    <Card>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <CardTitle>{t("ssl.settings")}</CardTitle>
        <Button variant="secondary" disabled={run.isPending} onClick={() => run.mutate()}>{t("ssl.runAll")}</Button>
      </div>
      <JobNotice jobId={jobId} onDone={() => void qc.invalidateQueries({ queryKey: ["certificates"] })} />
      <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-4">
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} /> {t("ssl.enabled")}
        </label>
        <div className="grid gap-4 md:grid-cols-3">
          <Field id="ssl-provider" label={t("ssl.provider")}>
            <select id="ssl-provider" className={selectClass} value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value as SettingsInput["provider"] })}>
              {(["letsencrypt", "letsencrypt-staging", "custom"] as const).map((p) => <option key={p} value={p}>{t(`ssl.providers.${p}`)}</option>)}
            </select>
          </Field>
          <Field id="ssl-email" label={t("ssl.email")}><Input id="ssl-email" type="email" value={form.email ?? ""} onChange={set("email")} /></Field>
          <Field id="ssl-host" label={t("ssl.hostname")}>
            <Input id="ssl-host" value={form.hostname ?? ""} onChange={set("hostname")} />
            <p className="text-xs text-slate-500">{t("ssl.hostnameHint")}</p>
          </Field>
        </div>
        {custom && (
          <div className="grid gap-4 md:grid-cols-2">
            <Field id="ssl-dir" label={t("ssl.directory")}><Input id="ssl-dir" placeholder="https://acme.example/directory" value={form.directory_url ?? ""} onChange={set("directory_url")} /></Field>
            <Field id="ssl-kid" label={t("ssl.eabKeyId")}><Input id="ssl-kid" value={form.eab_key_id ?? ""} onChange={set("eab_key_id")} /></Field>
            <Field id="ssl-eab" label={t("ssl.eabKey")}>
              <Input id="ssl-eab" type="password" autoComplete="off" placeholder={current.data?.has_eab_key ? t("ssl.eabKeyStored") : ""} value={form.eab_key ?? ""} onChange={set("eab_key")} />
            </Field>
            <Field id="ssl-ca" label={t("ssl.caBundle")}>
              <textarea id="ssl-ca" rows={4} className={textareaClass} value={form.ca_bundle ?? ""} onChange={set("ca_bundle")} spellCheck={false} />
            </Field>
          </div>
        )}
        <ErrorAlert error={save.error} />
        {save.isSuccess && <Alert kind="success">{t("common.saved")}</Alert>}
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
      </form>
    </Card>
  );
}
