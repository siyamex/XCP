import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { cn } from "../lib/cn";
import { ZoneList } from "./DnsPage";
import { DomainsPanel } from "./DomainsPage";
import { usePackages } from "./PackagesPage";

type Account = components["schemas"]["Account"];
type Status = Account["status"];

const statusStyle: Record<Status, string> = {
  creating: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-200",
  active: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200",
  suspended: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
  terminating: "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  error: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200",
};

export function StatusBadge({ status }: { status: Status }) {
  const { t } = useTranslation();
  return <span className={cn("rounded px-2 py-0.5 text-xs font-medium", statusStyle[status])}>{t(`accounts.statuses.${status}`)}</span>;
}

export function AccountsPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const list = useQuery({
    queryKey: ["accounts", search, status],
    queryFn: () => unwrap(api.GET("/accounts", { params: { query: { search: search || undefined, status: (status || undefined) as Status | undefined } } })),
    refetchInterval: (q) => (q.state.data?.items.some((a) => a.status === "creating" || a.status === "terminating") ? 2000 : false),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-bold">{t("accounts.title")}</h1>
        <Link to="/accounts/new"><Button>{t("accounts.new")}</Button></Link>
      </div>
      <div className="flex flex-wrap gap-2">
        <Input className="max-w-xs" placeholder={t("accounts.search")} value={search} onChange={(e) => setSearch(e.target.value)} />
        <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label={t("accounts.status")}
          className="rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
          <option value="">{t("accounts.allStatuses")}</option>
          {(Object.keys(statusStyle) as Status[]).map((s) => <option key={s} value={s}>{t(`accounts.statuses.${s}`)}</option>)}
        </select>
      </div>
      <ErrorAlert error={list.error} />
      {list.isPending ? <Spinner /> : (
        <Card className="overflow-x-auto p-0">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
              <tr>{["accounts.username", "accounts.domain", "accounts.package", "accounts.status", "accounts.created"].map((k) => (
                <th key={k} className="px-4 py-3 font-medium">{t(k)}</th>))}</tr>
            </thead>
            <tbody>
              {list.data?.items.map((a) => (
                <tr key={a.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="px-4 py-3">
                    <Link to="/accounts/$accountId" params={{ accountId: a.id }} className="font-medium text-brand hover:underline">{a.username}</Link>
                  </td>
                  <td className="px-4 py-3">{a.primary_domain}</td>
                  <td className="px-4 py-3">{a.package_name}</td>
                  <td className="px-4 py-3"><StatusBadge status={a.status} /></td>
                  <td className="px-4 py-3">{new Date(a.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
              {list.data?.items.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-6 text-center text-slate-500">{t("accounts.empty")}</td></tr>
              )}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

function usePHPVersions() {
  return useQuery({ queryKey: ["php-versions"], queryFn: () => unwrap(api.GET("/server/php-versions")), staleTime: 300_000 });
}

function PHPSelect({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation();
  const versions = usePHPVersions().data?.items ?? [];
  return (
    <select id={id} value={value} onChange={(e) => onChange(e.target.value)} className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
      <option value="">{t("accounts.phpDefault", { version: versions[versions.length - 1] ?? "?" })}</option>
      {versions.map((v) => <option key={v} value={v}>PHP {v}</option>)}
    </select>
  );
}

function generatePassword() {
  const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const out: string[] = [];
  const buf = new Uint8Array(64);
  while (out.length < 20) {
    crypto.getRandomValues(buf);
    for (const b of buf) if (b < 224 && out.length < 20) out.push(chars[b % chars.length]!); // 224 = 4 * 56: no bias
  }
  return out.join("");
}

export function AccountCreatePage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const packages = usePackages();
  const [form, setForm] = useState({ username: "", domain: "", package_id: "", email: "", password: "", php_version: "" });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  useEffect(() => {
    if (!form.package_id && packages.data?.items[0]) setForm((f) => ({ ...f, package_id: packages.data!.items[0]!.id }));
  }, [packages.data, form.package_id]);

  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts", { body: { ...form, email: form.email || undefined } })),
    onSuccess: async (a) => {
      await qc.invalidateQueries({ queryKey: ["accounts"] });
      await navigate({ to: "/accounts/$accountId", params: { accountId: a.id }, search: { job: a.job_id } as never });
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    create.mutate();
  }

  return (
    <form onSubmit={submit} className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t("accounts.new")}</h1>
        <Link to="/accounts"><Button type="button" variant="secondary">{t("common.back")}</Button></Link>
      </div>
      <ErrorAlert error={create.error} />
      <Card className="grid gap-4 md:grid-cols-2">
        <Field id="username" label={t("accounts.username")}>
          <Input id="username" required maxLength={16} pattern="[a-z][a-z0-9]{0,15}" autoComplete="off" value={form.username} onChange={set("username")} />
          <p className="text-xs text-slate-500">{t("accounts.usernameHint")}</p>
        </Field>
        <Field id="domain" label={t("accounts.domain")}>
          <Input id="domain" required placeholder="example.com" value={form.domain} onChange={set("domain")} />
        </Field>
        <Field id="package" label={t("accounts.package")}>
          <select id="package" required value={form.package_id} onChange={set("package_id")}
            className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
            {packages.data?.items.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </Field>
        <Field id="email" label={t("accounts.email")}>
          <Input id="email" type="email" value={form.email} onChange={set("email")} />
        </Field>
        <Field id="php" label={t("accounts.phpVersion")}>
          <PHPSelect id="php" value={form.php_version} onChange={(v) => setForm({ ...form, php_version: v })} />
        </Field>
        <Field id="password" label={t("accounts.password")}>
          <div className="flex gap-2">
            <Input id="password" required minLength={10} autoComplete="new-password" value={form.password} onChange={set("password")} />
            <Button type="button" variant="secondary" onClick={() => setForm({ ...form, password: generatePassword() })}>{t("accounts.generate")}</Button>
          </div>
        </Field>
      </Card>
      <Button type="submit" disabled={create.isPending}>{t("accounts.new")}</Button>
    </form>
  );
}

export function AccountDetailPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { accountId = "" } = useParams({ strict: false }) as { accountId?: string };
  const initialJob = new URLSearchParams(window.location.search).get("job") ?? undefined;
  const [jobId, setJobId] = useState<string | undefined>(initialJob);
  const account = useQuery({
    queryKey: ["accounts", accountId],
    queryFn: () => unwrap(api.GET("/accounts/{id}", { params: { path: { id: accountId } } })),
    retry: false,
  });
  const packages = usePackages();
  const [packageId, setPackageId] = useState("");
  const [email, setEmail] = useState("");
  const [php, setPhp] = useState("");
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [mustChange, setMustChange] = useState(true);
  const [confirm, setConfirm] = useState("");

  useEffect(() => {
    if (account.data) {
      setPackageId(account.data.package_id);
      setEmail(account.data.email);
      setPhp(account.data.php_version);
    }
  }, [account.data]);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["accounts"] });
  };
  const started = (a: Account) => {
    setJobId(a.job_id);
    refresh();
  };
  const path = { params: { path: { id: accountId } } };
  const update = useMutation({ mutationFn: () => unwrap(api.PUT("/accounts/{id}", { ...path, body: { package_id: packageId, email, php_version: php } })), onSuccess: started });
  const suspend = useMutation({ mutationFn: () => unwrap(api.POST("/accounts/{id}/suspend", { ...path, body: { reason } })), onSuccess: started });
  const unsuspend = useMutation({ mutationFn: () => unwrap(api.POST("/accounts/{id}/unsuspend", path)), onSuccess: started });
  const setPw = useMutation({ mutationFn: () => unwrap(api.POST("/accounts/{id}/password", { ...path, body: { password, must_change: mustChange } })), onSuccess: () => setPassword("") });
  const terminate = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/terminate", { ...path, body: { confirm } })),
    onSuccess: (a) => { started(a); void navigate({ to: "/accounts" }); },
  });

  if (account.isPending) return <Spinner />;
  if (!account.data) return <ErrorAlert error={account.error} />;
  const a = account.data;
  const error = update.error ?? suspend.error ?? unsuspend.error ?? setPw.error ?? terminate.error;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-3 text-2xl font-bold">{a.username} <StatusBadge status={a.status} /></h1>
        <Link to="/accounts"><Button variant="secondary">{t("common.back")}</Button></Link>
      </div>
      <JobNotice jobId={jobId} onDone={refresh} />
      <ErrorAlert error={error} />
      {a.status_detail && <Alert kind={a.status === "error" ? "error" : "info"}>{a.status_detail}</Alert>}

      <Card>
        <CardTitle>{t("accounts.details")}</CardTitle>
        <dl className="grid gap-3 text-sm sm:grid-cols-2">
          {[["accounts.domain", a.primary_domain], ["accounts.uid", String(a.uid)], ["accounts.package", a.package_name], ["accounts.phpVersion", a.php_version || "default"],
            ["accounts.created", new Date(a.created_at).toLocaleString()]].map(([k, v]) => (
            <div key={k}><dt className="text-slate-500">{t(k!)}</dt><dd className="font-medium">{v}</dd></div>
          ))}
        </dl>
      </Card>

      {(a.status === "active" || a.status === "suspended") && <DomainsPanel accountId={a.id} />}
      {(a.status === "active" || a.status === "suspended") && (
        <div className="space-y-2">
          <h2 className="text-lg font-semibold">{t("dns.title")}</h2>
          <ZoneList accountId={a.id} />
        </div>
      )}

      <Card>
        <CardTitle>{t("accounts.change")}</CardTitle>
        <form onSubmit={(e) => { e.preventDefault(); update.mutate(); }} className="grid gap-4 md:grid-cols-2">
          <Field id="pkg" label={t("accounts.package")}>
            <select id="pkg" value={packageId} onChange={(e) => setPackageId(e.target.value)}
              className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
              {packages.data?.items.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </Field>
          <Field id="acc-email" label={t("accounts.email")}>
            <Input id="acc-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Field id="acc-php" label={t("accounts.phpVersion")}>
            <PHPSelect id="acc-php" value={php} onChange={setPhp} />
          </Field>
          <div><Button type="submit" disabled={update.isPending}>{t("accounts.saveChanges")}</Button></div>
        </form>
      </Card>

      <Card>
        <CardTitle>{a.status === "suspended" ? t("accounts.unsuspend") : t("accounts.suspend")}</CardTitle>
        {a.status === "suspended" ? (
          <Button onClick={() => unsuspend.mutate()} disabled={unsuspend.isPending}>{t("accounts.unsuspend")}</Button>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); suspend.mutate(); }} className="flex max-w-xl flex-wrap items-end gap-2">
            <div className="flex-1">
              <Field id="reason" label={t("accounts.suspendReason")}>
                <Input id="reason" maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
              </Field>
            </div>
            <Button type="submit" variant="secondary" disabled={suspend.isPending || a.status !== "active"}>{t("accounts.suspend")}</Button>
          </form>
        )}
      </Card>

      <Card>
        <CardTitle>{t("accounts.resetPassword")}</CardTitle>
        <form onSubmit={(e) => { e.preventDefault(); setPw.mutate(); }} className="max-w-md space-y-3">
          <Field id="newpw" label={t("accounts.newPassword")}>
            <Input id="newpw" required minLength={10} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={mustChange} onChange={(e) => setMustChange(e.target.checked)} /> {t("accounts.mustChange")}
          </label>
          {setPw.isSuccess && <Alert kind="success">{t("accounts.passwordSet")}</Alert>}
          <Button type="submit" variant="secondary" disabled={setPw.isPending}>{t("accounts.resetPassword")}</Button>
        </form>
      </Card>

      <Card className="border-red-200 dark:border-red-900">
        <CardTitle>{t("accounts.terminate")}</CardTitle>
        <p className="mb-3 text-sm">{t("accounts.terminateHelp")}</p>
        <form onSubmit={(e) => { e.preventDefault(); terminate.mutate(); }} className="flex max-w-xl flex-wrap items-end gap-2">
          <div className="flex-1">
            <Field id="confirm" label={t("accounts.terminateConfirm", { name: a.username })}>
              <Input id="confirm" autoComplete="off" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </Field>
          </div>
          <Button type="submit" variant="danger" disabled={confirm !== a.username || terminate.isPending}>{t("accounts.terminate")}</Button>
        </form>
      </Card>
    </div>
  );
}
