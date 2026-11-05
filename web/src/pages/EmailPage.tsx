import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { MailQueueCard } from "./MailQueueCard";
import { SpamCard } from "./SpamCard";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { cn } from "../lib/cn";
import { generatePassword } from "../lib/password";

type Overview = components["schemas"]["MailOverview"];
type MailDomain = components["schemas"]["MailDomain"];
type Mailbox = components["schemas"]["Mailbox"];
type Check = components["schemas"]["DeliverabilityCheck"];
type SettingsInput = components["schemas"]["MailSettings"] & { relay_password?: string };

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";
const checkStyle: Record<string, string> = {
  ok: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200",
  warning: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
  error: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200",
};

/** Email: the account's mail for users, the mail server's settings for admins. */
export function EmailPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("email.title")}</h1>
      {me.data?.role === "admin" ? <><SettingsCard /><MailQueueCard /></>
        : me.data?.account_id ? <AccountMail accountId={me.data.account_id} /> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

/** One account's mail (USR-MAIL-01, 03, 06, 09). */
export function AccountMail({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const key = ["mail", accountId];
  const overview = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/accounts/{id}/mail", { params: { path: { id: accountId } } })),
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
  const own = o.domains.filter((d) => !d.alias_of);
  return (
    <div className="space-y-6">
      <JobNotice jobId={jobId} onDone={refresh} />
      <Mailboxes accountId={accountId} o={o} domains={own} onStarted={started} />
      <Forwarders accountId={accountId} o={o} domains={own} onStarted={started} />
      {o.mailboxes.length > 0 && <SpamCard mailboxes={o.mailboxes.map((m) => ({ id: m.id, address: m.address }))} onStarted={started} />}
      <Card className="space-y-4">
        <CardTitle>{t("email.domains")}</CardTitle>
        {o.domains.map((d) => <DomainMail key={d.id} d={d} onStarted={started} />)}
      </Card>
      <ClientSettings server={o.server} />
    </div>
  );
}

function Usage({ used, max }: { used: number; max: number | null | undefined }) {
  const { t } = useTranslation();
  return <span className="text-xs text-slate-500">{max == null ? t("databases.used", { used }) : t("databases.usedOf", { used, max })}</span>;
}

/** Picks a domain for a new address: name@domain. */
function AddressInput({ id, domains, local, domainId, onChange }: {
  id: string; domains: MailDomain[]; local: string; domainId: string; onChange: (local: string, domainId: string) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="flex items-center gap-1 text-sm">
      <Input id={id} className="max-w-[12rem]" required placeholder={t("email.name")} value={local} onChange={(e) => onChange(e.target.value, domainId)} />
      <span className="text-slate-500">@</span>
      <select aria-label={t("email.domain")} className={selectClass} value={domainId} onChange={(e) => onChange(local, e.target.value)}>
        {domains.map((d) => <option key={d.id} value={d.id}>{d.display_name}</option>)}
      </select>
    </div>
  );
}

function Mailboxes({ accountId, o, domains, onStarted }: { accountId: string; o: Overview; domains: MailDomain[]; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [form, setForm] = useState({ local: "", domain_id: domains[0]?.id ?? "", password: "", quota_mb: 0 });
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/mailboxes", { params: { path: { id: accountId } }, body: form })),
    onSuccess: (r) => { setForm({ ...form, local: "", password: "" }); onStarted(r); },
  });
  return (
    <Card className="overflow-x-auto p-0">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
        <CardTitle>{t("email.mailboxes")}</CardTitle>
        <Usage used={o.mailboxes.length} max={o.max_mailboxes} />
      </div>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["email.address", "email.quota", "email.switches", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {o.mailboxes.map((m) => <MailboxRow key={m.id} m={m} maxQuota={o.max_quota_mb} onStarted={onStarted} />)}
          {o.mailboxes.length === 0 && <tr><td colSpan={4} className="px-4 py-6 text-center text-slate-500">{t("email.noMailboxes")}</td></tr>}
        </tbody>
      </table>
      {domains.length > 0 && (
        <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="flex flex-wrap items-end gap-3 border-t border-slate-100 p-4 dark:border-slate-800">
          <Field id="mb-local" label={t("email.newMailbox")}>
            <AddressInput id="mb-local" domains={domains} local={form.local} domainId={form.domain_id} onChange={(local, domain_id) => setForm({ ...form, local, domain_id })} />
          </Field>
          <Field id="mb-pw" label={t("databases.password")}>
            <div className="flex gap-1">
              <Input id="mb-pw" required autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <Button type="button" variant="ghost" onClick={() => setForm({ ...form, password: generatePassword() })}>{t("databases.generate")}</Button>
            </div>
          </Field>
          <Field id="mb-quota" label={t("email.quotaMB")}>
            <Input id="mb-quota" type="number" min={0} className="w-28" value={form.quota_mb || ""} placeholder={o.max_quota_mb ? String(o.max_quota_mb) : t("common.unlimited")}
              onChange={(e) => setForm({ ...form, quota_mb: Number(e.target.value) })} />
          </Field>
          <Button type="submit" variant="secondary" disabled={create.isPending}>{t("email.createMailbox")}</Button>
          <div className="w-full"><ErrorAlert error={create.error} /></div>
        </form>
      )}
    </Card>
  );
}

function MailboxRow({ m, maxQuota, onStarted }: { m: Mailbox; maxQuota: number | null | undefined; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [quota, setQuota] = useState(m.quota_mb);
  const [password, setPassword] = useState("");
  const path = { params: { path: { id: m.id } } };
  const update = useMutation({
    mutationFn: (b: { quota_mb: number; login: boolean; receive: boolean; send: boolean }) => unwrap(api.PUT("/mailboxes/{id}", { ...path, body: b })),
    onSuccess: onStarted,
  });
  const setPw = useMutation({
    mutationFn: () => unwrap(api.PUT("/mailboxes/{id}/password", { ...path, body: { password } })),
    onSuccess: (r) => { setPassword(""); onStarted(r); },
  });
  const remove = useMutation({ mutationFn: () => unwrap(api.DELETE("/mailboxes/{id}", path)), onSuccess: onStarted });
  const flags = { quota_mb: m.quota_mb, login: m.login, receive: m.receive, send: m.send };
  return (
    <>
      <tr className="border-t border-slate-100 align-top dark:border-slate-800">
        <td className="px-4 py-3 font-medium">
          {m.address}
          {m.autoresponder && <span className="ml-2 rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-800 dark:bg-amber-950 dark:text-amber-200">{t("email.replying")}</span>}
        </td>
        <td className="px-4 py-3">{m.quota_mb ? `${m.quota_mb} MB` : t("common.unlimited")}</td>
        <td className="px-4 py-3">
          <div className="flex flex-wrap gap-3 text-xs">
            {(["login", "receive", "send"] as const).map((k) => (
              <label key={k} className="flex items-center gap-1">
                <input type="checkbox" checked={m[k]} disabled={update.isPending} onChange={(e) => update.mutate({ ...flags, [k]: e.target.checked })} />
                {t(`email.${k}`)}
              </label>
            ))}
          </div>
        </td>
        <td className="whitespace-nowrap px-4 py-3 text-right">
          {m.login && <WebmailButton mailboxId={m.id} />}
          <Button variant="ghost" onClick={() => setOpen(!open)}>{open ? t("common.cancel") : t("databases.manage")}</Button>
          <Button variant="ghost" disabled={remove.isPending}
            onClick={() => window.confirm(t("email.confirmDelete", { name: m.address })) && remove.mutate()}>{t("common.delete")}</Button>
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50 dark:bg-slate-900/50">
          <td colSpan={4} className="space-y-3 px-4 py-4">
            <ErrorAlert error={update.error ?? setPw.error ?? remove.error} />
            <form onSubmit={(e) => { e.preventDefault(); update.mutate({ ...flags, quota_mb: quota }); }} className="flex flex-wrap items-end gap-2">
              <Field id={`q-${m.id}`} label={t("email.quotaMB")}>
                <Input id={`q-${m.id}`} type="number" min={0} className="w-28" value={quota || ""} placeholder={maxQuota ? String(maxQuota) : t("common.unlimited")}
                  onChange={(e) => setQuota(Number(e.target.value))} />
              </Field>
              <Button type="submit" variant="secondary" disabled={update.isPending}>{t("email.saveQuota")}</Button>
            </form>
            <AutoresponderForm m={m} onStarted={onStarted} />
            <form onSubmit={(e) => { e.preventDefault(); setPw.mutate(); }} className="flex flex-wrap items-end gap-2">
              <Field id={`pw-${m.id}`} label={t("databases.newPassword")}>
                <Input id={`pw-${m.id}`} required autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
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

/** Opens webmail in a new tab, signed in with a one-time URL. */
function WebmailButton({ mailboxId }: { mailboxId: string }) {
  const { t } = useTranslation();
  const signon = useMutation({
    mutationFn: () => unwrap(api.POST("/mailboxes/{id}/webmail", { params: { path: { id: mailboxId } } })),
  });
  const open = () => {
    // Open the tab while the click still counts, then send it to the URL.
    const tab = window.open("about:blank", "_blank");
    if (tab) tab.opener = null;
    signon.mutate(undefined, {
      onSuccess: (r) => (tab ? tab.location.replace(r.url) : window.location.assign(r.url)),
      onError: () => tab?.close(),
    });
  };
  return (
    <span className="inline-block text-left">
      <Button variant="ghost" disabled={signon.isPending} onClick={open}>{t("email.webmail")}</Button>
      <ErrorAlert error={signon.error} />
    </span>
  );
}

/** A mailbox's autoresponder (USR-MAIL-05). */
function AutoresponderForm({ m, onStarted }: { m: Mailbox; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const blank = { subject: "", body: "", start: "", end: "", days: 1 };
  const [form, setForm] = useState({ ...blank, ...m.autoresponder });
  const path = { params: { path: { id: m.id } } };
  const save = useMutation({ mutationFn: () => unwrap(api.PUT("/mailboxes/{id}/autoresponder", { ...path, body: form })), onSuccess: onStarted });
  const remove = useMutation({
    mutationFn: () => unwrap(api.DELETE("/mailboxes/{id}/autoresponder", path)),
    onSuccess: (r) => { setForm(blank); onStarted(r); },
  });
  return (
    <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-3">
      <p className="text-sm font-medium">{t("email.autoresponder")}</p>
      <div className="grid gap-3 md:grid-cols-4">
        <Field id={`ar-s-${m.id}`} label={t("email.subject")}>
          <Input id={`ar-s-${m.id}`} required value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} />
        </Field>
        <Field id={`ar-from-${m.id}`} label={t("email.from")}>
          <Input id={`ar-from-${m.id}`} type="date" value={form.start ?? ""} onChange={(e) => setForm({ ...form, start: e.target.value })} />
        </Field>
        <Field id={`ar-to-${m.id}`} label={t("email.until")}>
          <Input id={`ar-to-${m.id}`} type="date" value={form.end ?? ""} onChange={(e) => setForm({ ...form, end: e.target.value })} />
        </Field>
        <Field id={`ar-d-${m.id}`} label={t("email.everyDays")}>
          <Input id={`ar-d-${m.id}`} type="number" min={1} max={30} value={form.days ?? 1} onChange={(e) => setForm({ ...form, days: Number(e.target.value) })} />
        </Field>
      </div>
      <textarea aria-label={t("email.replyText")} required rows={4} placeholder={t("email.replyText")}
        className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900"
        value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} />
      <ErrorAlert error={save.error ?? remove.error} />
      <div className="flex gap-2">
        <Button type="submit" variant="secondary" disabled={save.isPending}>{t("email.saveReply")}</Button>
        {m.autoresponder && <Button type="button" variant="ghost" disabled={remove.isPending} onClick={() => remove.mutate()}>{t("email.removeReply")}</Button>}
      </div>
    </form>
  );
}

function Forwarders({ accountId, o, domains, onStarted }: { accountId: string; o: Overview; domains: MailDomain[]; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [form, setForm] = useState({ local: "", domain_id: domains[0]?.id ?? "", to: "", fail: "", pipe: "", mode: "forward" as "forward" | "reject" | "pipe" });
  const create = useMutation({
    mutationFn: () => {
      const base = { domain_id: form.domain_id, local: form.local };
      const body = form.mode === "reject" ? { ...base, fail: form.fail }
        : form.mode === "pipe" ? { ...base, pipe: form.pipe }
        : { ...base, to: form.to.split(/[\s,;]+/).filter(Boolean) };
      return unwrap(api.POST("/accounts/{id}/forwarders", { params: { path: { id: accountId } }, body }));
    },
    onSuccess: (r) => { setForm({ ...form, local: "", to: "", fail: "", pipe: "" }); onStarted(r); },
  });
  const remove = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/forwarders/{id}", { params: { path: { id } } })),
    onSuccess: onStarted,
  });
  return (
    <Card className="overflow-x-auto p-0">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
        <CardTitle>{t("email.forwarders")}</CardTitle>
        <Usage used={o.forwarders.length} max={o.max_forwarders} />
      </div>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["email.address", "email.goesTo", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {o.forwarders.map((f) => (
            <tr key={f.id} className="border-t border-slate-100 dark:border-slate-800">
              <td className="px-4 py-3 font-medium">{f.address}</td>
              <td className="px-4 py-3">{f.fail ? <span className="text-red-700 dark:text-red-400">{t("email.rejected", { message: f.fail })}</span>
                : f.pipe ? <span className="font-mono text-xs">{t("email.piped", { script: f.pipe })}</span> : f.to.join(", ")}</td>
              <td className="px-4 py-3 text-right">
                <Button variant="ghost" disabled={remove.isPending} onClick={() => remove.mutate(f.id)}>{t("common.delete")}</Button>
              </td>
            </tr>
          ))}
          {o.forwarders.length === 0 && <tr><td colSpan={3} className="px-4 py-6 text-center text-slate-500">{t("email.noForwarders")}</td></tr>}
        </tbody>
      </table>
      {domains.length > 0 && (
        <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="space-y-3 border-t border-slate-100 p-4 dark:border-slate-800">
          <div className="flex flex-wrap items-end gap-3">
            <Field id="fw-local" label={t("email.newForwarder")}>
              <AddressInput id="fw-local" domains={domains} local={form.local} domainId={form.domain_id} onChange={(local, domain_id) => setForm({ ...form, local, domain_id })} />
            </Field>
            <div className="flex gap-4 pb-2 text-sm">
              {(["forward", "reject", "pipe"] as const).map((mode) => (
                <label key={mode} className="flex items-center gap-1">
                  <input type="radio" checked={form.mode === mode} onChange={() => setForm({ ...form, mode })} /> {t(`email.modes.${mode}`)}
                </label>
              ))}
            </div>
          </div>
          {form.mode === "reject" && <Input aria-label={t("email.rejectMessage")} required placeholder={t("email.rejectMessage")} value={form.fail} onChange={(e) => setForm({ ...form, fail: e.target.value })} />}
          {form.mode === "forward" && <Input aria-label={t("email.targets")} required placeholder={t("email.targets")} value={form.to} onChange={(e) => setForm({ ...form, to: e.target.value })} />}
          {form.mode === "pipe" && <>
            <Input aria-label={t("email.script")} required placeholder="bin/handle-mail.php" value={form.pipe} onChange={(e) => setForm({ ...form, pipe: e.target.value })} />
            <p className="text-xs text-slate-500">{t("email.scriptHint")}</p>
          </>}
          <ErrorAlert error={create.error ?? remove.error} />
          <Button type="submit" variant="secondary" disabled={create.isPending}>{t("email.createForwarder")}</Button>
        </form>
      )}
    </Card>
  );
}

/** A domain's routing, default address and deliverability check. */
function DomainMail({ d, onStarted }: { d: MailDomain; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [catchAll, setCatchAll] = useState(d.catch_all.join(", "));
  const [checking, setChecking] = useState(false);
  const path = { params: { path: { id: d.id } } };
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/domains/{id}/mail/catch-all", { ...path, body: { to: catchAll.split(/[\s,;]+/).filter(Boolean) } })),
    onSuccess: onStarted,
  });
  const check = useQuery({
    queryKey: ["deliverability", d.id],
    queryFn: () => unwrap(api.GET("/domains/{id}/mail/deliverability", path)),
    enabled: checking, retry: false,
  });
  const repair = useMutation({
    mutationFn: () => unwrap(api.POST("/domains/{id}/mail/repair", path)),
    onSuccess: () => void check.refetch(),
  });
  return (
    <div className="space-y-3 border-t border-slate-100 pt-4 first:border-0 first:pt-0 dark:border-slate-800">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{d.display_name}</span>
        <span className="rounded bg-slate-100 px-2 py-0.5 text-xs dark:bg-slate-800">{t(`email.routing.${d.routing}`)}</span>
        {d.alias_of && <span className="text-xs text-slate-500">{t("email.aliasOf", { name: d.alias_of })}</span>}
      </div>
      {!d.alias_of && d.routing === "local" && (
        <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="flex flex-wrap items-end gap-2">
          <Field id={`ca-${d.id}`} label={t("email.catchAll")}>
            <Input id={`ca-${d.id}`} className="min-w-[18rem]" placeholder={t("email.catchAllReject")} value={catchAll} onChange={(e) => setCatchAll(e.target.value)} />
          </Field>
          <Button type="submit" variant="secondary" disabled={save.isPending}>{t("common.save")}</Button>
          <div className="w-full"><ErrorAlert error={save.error} /></div>
        </form>
      )}
      {!d.alias_of && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-2">
            <Button variant="ghost" disabled={check.isFetching} onClick={() => (checking ? void check.refetch() : setChecking(true))}>{t("email.check")}</Button>
            {check.data?.repairable && <Button variant="ghost" disabled={repair.isPending} onClick={() => repair.mutate()}>{t("email.repair")}</Button>}
          </div>
          {check.isFetching && <Spinner />}
          <ErrorAlert error={check.error ?? repair.error} />
          {repair.data && <Alert kind="info">{repair.data.changed ? t("email.repaired") : t("email.nothingToRepair")}</Alert>}
          {check.data && <Checks checks={check.data.checks} />}
        </div>
      )}
    </div>
  );
}

function Checks({ checks }: { checks: Check[] }) {
  const { t } = useTranslation();
  return (
    <ul className="space-y-2 text-sm">
      {checks.map((c) => (
        <li key={c.name} className="flex flex-wrap items-start gap-2">
          <span className={cn("w-16 rounded px-2 py-0.5 text-center text-xs font-medium uppercase", checkStyle[c.status])}>{c.name}</span>
          <div className="min-w-0 flex-1">
            <p>{c.detail}</p>
            {c.found.length > 0 && <p className="break-all font-mono text-xs text-slate-500">{c.found.join(" | ")}</p>}
            {c.status !== "ok" && c.expected && <p className="break-all font-mono text-xs text-slate-500">{t("email.expected")}: {c.expected}</p>}
          </div>
        </li>
      ))}
    </ul>
  );
}

/** What to enter in a mail client. */
function ClientSettings({ server }: { server: string }) {
  const { t } = useTranslation();
  const rows: [string, string][] = [
    ["Webmail", `https://${server}/webmail/`],
    ["IMAP", `${server} · 993 · SSL/TLS`], ["POP3", `${server} · 995 · SSL/TLS`], ["SMTP", `${server} · 587 · STARTTLS (465 · SSL/TLS)`],
  ];
  return (
    <Card>
      <CardTitle>{t("email.clients")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("email.clientsHint")}</p>
      <dl className="grid gap-2 font-mono text-sm sm:grid-cols-[6rem_1fr]">
        {rows.map(([k, v]) => <Fragment key={k}><dt className="text-slate-500">{k}</dt><dd>{v}</dd></Fragment>)}
      </dl>
    </Card>
  );
}

/** The mail server's settings for admins (ADM-MAIL-01). */
function SettingsCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const current = useQuery({ queryKey: ["mail-settings"], queryFn: () => unwrap(api.GET("/server/mail")), retry: false });
  const [form, setForm] = useState<SettingsInput>();
  const [rbls, setRbls] = useState("");
  const [spamAllow, setSpamAllow] = useState("");
  const [spamBlock, setSpamBlock] = useState("");
  useEffect(() => {
    if (current.data && !form) {
      setForm({ ...current.data, relay_password: "" });
      setRbls(current.data.rbls.join("\n"));
      setSpamAllow(current.data.spam_allow.join("\n"));
      setSpamBlock(current.data.spam_block.join("\n"));
    }
  }, [current.data, form]);
  const save = useMutation({
    mutationFn: () => {
      const { has_relay_password: _, ...rest } = form!;
      return unwrap(api.PUT("/server/mail", { body: { ...rest, rbls: rbls.split(/\s+/).filter(Boolean), spam_allow: spamAllow.split(/[\s,]+/).filter(Boolean), spam_block: spamBlock.split(/[\s,]+/).filter(Boolean) } }));
    },
    onSuccess: (r) => {
      setJobId(r.job_id);
      void qc.invalidateQueries({ queryKey: ["mail-settings"] });
    },
  });
  if (!form) return current.error ? <ErrorAlert error={current.error} /> : <Spinner />;
  const set = (k: keyof SettingsInput) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  return (
    <Card>
      <CardTitle>{t("email.settings")}</CardTitle>
      <JobNotice jobId={jobId} onDone={() => undefined} />
      <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <Field id="m-host" label={t("email.hostname")}>
            <Input id="m-host" required value={form.hostname} onChange={set("hostname")} />
            <p className="text-xs text-slate-500">{t("email.hostnameHint")}</p>
          </Field>
          <Field id="m-size" label={t("email.maxMessage")}>
            <Input id="m-size" type="number" min={1} max={1024} value={form.max_message_mb} onChange={(e) => setForm({ ...form, max_message_mb: Number(e.target.value) })} />
          </Field>
          <Field id="m-relay" label={t("email.relayHost")}>
            <Input id="m-relay" placeholder="smtp.example.com:587" value={form.relay_host} onChange={set("relay_host")} />
            <p className="text-xs text-slate-500">{t("email.relayHint")}</p>
          </Field>
          <Field id="m-ruser" label={t("email.relayUser")}><Input id="m-ruser" value={form.relay_user} onChange={set("relay_user")} /></Field>
          <Field id="m-rpass" label={t("email.relayPassword")}>
            <Input id="m-rpass" type="password" autoComplete="off" placeholder={form.has_relay_password ? t("ssl.eabKeyStored") : ""}
              value={form.relay_password ?? ""} onChange={set("relay_password")} />
          </Field>
          <Field id="m-rbl" label={t("email.rbls")}>
            <textarea id="m-rbl" rows={3} className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900"
              placeholder="zen.spamhaus.org" value={rbls} onChange={(e) => setRbls(e.target.value)} />
          </Field>
        </div>
        <div className="flex flex-wrap gap-6 text-sm">
          <label className="flex items-center gap-2"><input type="checkbox" checked={form.helo_checks} onChange={(e) => setForm({ ...form, helo_checks: e.target.checked })} /> {t("email.heloChecks")}</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={form.greylisting} onChange={(e) => setForm({ ...form, greylisting: e.target.checked })} /> {t("email.greylisting")}</label>
        </div>
        <fieldset className="space-y-3 border-t border-slate-200 pt-4 dark:border-slate-800">
          <legend className="text-sm font-semibold">{t("email.serverSpam.title")}</legend>
          <p className="text-sm text-slate-500">{t("email.serverSpam.hint")}</p>
          <div className="grid gap-4 md:grid-cols-3">
            <Field id="m-reject" label={t("email.serverSpam.reject")}>
              <Input id="m-reject" type="number" min={8} max={100} value={form.spam_reject} onChange={(e) => setForm({ ...form, spam_reject: Number(e.target.value) })} />
              <p className="text-xs text-slate-500">{t("email.serverSpam.rejectHint")}</p>
            </Field>
            <Field id="m-sallow" label={t("email.serverSpam.allow")}>
              <textarea id="m-sallow" rows={3} className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900" placeholder="partner.example" value={spamAllow} onChange={(e) => setSpamAllow(e.target.value)} />
              <p className="text-xs text-slate-500">{t("email.serverSpam.allowHint")}</p>
            </Field>
            <Field id="m-sblock" label={t("email.serverSpam.block")}>
              <textarea id="m-sblock" rows={3} className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900" placeholder="spammer@bad.example" value={spamBlock} onChange={(e) => setSpamBlock(e.target.value)} />
              <p className="text-xs text-slate-500">{t("email.serverSpam.blockHint")}</p>
            </Field>
          </div>
        </fieldset>
        <ErrorAlert error={save.error} />
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
      </form>
    </Card>
  );
}
