import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { generatePassword } from "../lib/password";

type Overview = components["schemas"]["DatabaseOverview"];
type Database = components["schemas"]["Database"];
type DBUser = components["schemas"]["DatabaseUser"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";


function formatSize(bytes: number | null | undefined) {
  if (bytes == null) return "-";
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Databases: the server for admins, the account's databases and users for users. */
export function DatabasesPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("databases.title")}</h1>
      {me.data?.role === "admin" ? <ServerCard />
        : me.data?.account_id ? <AccountDatabases accountId={me.data.account_id} /> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

/** Opens phpMyAdmin in a new tab with a one-time sign-on URL. */
function PhpMyAdminButton({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const signon = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/phpmyadmin", { params: { path: { id: accountId } } })),
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
    <div className="space-y-2">
      <Button variant="secondary" disabled={signon.isPending} onClick={open}>{t("databases.phpmyadmin")}</Button>
      <ErrorAlert error={signon.error} />
    </div>
  );
}

/** One account's databases, users and privileges (USR-DB-01..04). */
export function AccountDatabases({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const key = ["databases", accountId];
  const overview = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/accounts/{id}/databases", { params: { path: { id: accountId } } })),
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
      <div className="flex flex-wrap items-start justify-between gap-4">
        <p className="max-w-xl text-sm text-slate-600 dark:text-slate-400">{t("databases.intro", { prefix: o.prefix, host: o.host })}</p>
        {o.phpmyadmin && <PhpMyAdminButton accountId={accountId} />}
      </div>
      {o.server !== "ok" && <Alert kind="info">{o.server}</Alert>}
      <JobNotice jobId={jobId} onDone={refresh} />
      <Wizard accountId={accountId} o={o} onStarted={started} />
      <DatabaseList accountId={accountId} o={o} onStarted={started} />
      <UserList accountId={accountId} o={o} onStarted={started} />
    </div>
  );
}

/** How many the account has, and of how many if the package limits it. */
function Usage({ used, max }: { used: number; max: number | null | undefined }) {
  const { t } = useTranslation();
  return <span className="text-xs text-slate-500">{max == null ? t("databases.used", { used }) : t("databases.usedOf", { used, max })}</span>;
}

function Wizard({ accountId, o, onStarted }: { accountId: string; o: Overview; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [form, setForm] = useState({ database: "", user: "", password: "" });
  const [shown, setShown] = useState<{ database: string; user: string; password: string }>();
  const run = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/database-wizard", { params: { path: { id: accountId } }, body: form })),
    onSuccess: (r) => {
      setShown({ database: r.database.name, user: r.user.name, password: form.password });
      setForm({ database: "", user: "", password: "" });
      onStarted(r);
    },
  });
  return (
    <Card>
      <CardTitle>{t("databases.wizard")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("databases.wizardHint")}</p>
      <form onSubmit={(e) => { e.preventDefault(); run.mutate(); }} className="grid items-end gap-3 md:grid-cols-4">
        <Field id="wz-db" label={t("databases.database")}>
          <div className="flex items-center gap-1 text-sm"><span className="text-slate-500">{o.prefix}</span>
            <Input id="wz-db" required value={form.database} onChange={(e) => setForm({ ...form, database: e.target.value })} /></div>
        </Field>
        <Field id="wz-user" label={t("databases.user")}>
          <div className="flex items-center gap-1 text-sm"><span className="text-slate-500">{o.prefix}</span>
            <Input id="wz-user" required value={form.user} onChange={(e) => setForm({ ...form, user: e.target.value })} /></div>
        </Field>
        <Field id="wz-pw" label={t("databases.password")}>
          <div className="flex gap-1">
            <Input id="wz-pw" required autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <Button type="button" variant="ghost" onClick={() => setForm({ ...form, password: generatePassword() })}>{t("databases.generate")}</Button>
          </div>
        </Field>
        <Button type="submit" disabled={run.isPending}>{t("databases.create")}</Button>
      </form>
      <div className="mt-3"><ErrorAlert error={run.error} /></div>
      {shown && (
        <div className="mt-3 rounded-md bg-slate-50 p-3 font-mono text-sm dark:bg-slate-900">
          <p className="mb-1 font-sans text-xs text-slate-500">{t("databases.connectionInfo")}</p>
          <div>DB_HOST={o.host}</div><div>DB_NAME={shown.database}</div><div>DB_USER={shown.user}</div><div>DB_PASSWORD={shown.password}</div>
        </div>
      )}
    </Card>
  );
}

function DatabaseList({ accountId, o, onStarted }: { accountId: string; o: Overview; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/databases", { params: { path: { id: accountId } }, body: { name } })),
    onSuccess: (r) => { setName(""); onStarted(r); },
  });
  return (
    <Card className="overflow-x-auto p-0">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
        <CardTitle>{t("databases.databases")}</CardTitle>
        <Usage used={o.databases.length} max={o.max_databases} />
      </div>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["databases.name", "databases.size", "databases.users", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {o.databases.map((d) => <DatabaseRow key={d.id} d={d} prefix={o.prefix} onStarted={onStarted} />)}
          {o.databases.length === 0 && <tr><td colSpan={4} className="px-4 py-6 text-center text-slate-500">{t("databases.noDatabases")}</td></tr>}
        </tbody>
      </table>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="flex flex-wrap items-center gap-2 border-t border-slate-100 p-4 text-sm dark:border-slate-800">
        <label htmlFor="new-db" className="text-slate-500">{o.prefix}</label>
        <Input id="new-db" className="max-w-xs" required placeholder={t("databases.newDatabase")} value={name} onChange={(e) => setName(e.target.value)} />
        <Button type="submit" variant="secondary" disabled={create.isPending}>{t("databases.createDatabase")}</Button>
        <div className="w-full"><ErrorAlert error={create.error} /></div>
      </form>
    </Card>
  );
}

function DatabaseRow({ d, prefix, onStarted }: { d: Database; prefix: string; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(d.name.slice(prefix.length));
  const path = { params: { path: { id: d.id } } };
  const rename = useMutation({
    mutationFn: () => unwrap(api.PUT("/databases/{id}", { ...path, body: { name } })),
    onSuccess: (r) => { setRenaming(false); onStarted(r); },
  });
  const remove = useMutation({ mutationFn: () => unwrap(api.DELETE("/databases/{id}", path)), onSuccess: onStarted });
  return (
    <tr className="border-t border-slate-100 align-top dark:border-slate-800">
      <td className="px-4 py-3 font-medium">
        {renaming ? (
          <form onSubmit={(e) => { e.preventDefault(); rename.mutate(); }} className="flex items-center gap-1">
            <span className="font-normal text-slate-500">{prefix}</span>
            <Input aria-label={t("databases.newName")} value={name} onChange={(e) => setName(e.target.value)} />
            <Button type="submit" variant="secondary" disabled={rename.isPending}>{t("common.save")}</Button>
          </form>
        ) : d.name}
        <ErrorAlert error={rename.error ?? remove.error} />
      </td>
      <td className="px-4 py-3">{formatSize(d.size_bytes)}</td>
      <td className="px-4 py-3">{d.users.length ? d.users.map((u) => u.name).join(", ") : <span className="text-slate-500">{t("common.none")}</span>}</td>
      <td className="whitespace-nowrap px-4 py-3 text-right">
        <Button variant="ghost" onClick={() => setRenaming(!renaming)}>{renaming ? t("common.cancel") : t("databases.rename")}</Button>
        <Button variant="ghost" disabled={remove.isPending}
          onClick={() => window.confirm(t("databases.confirmDelete", { name: d.name })) && remove.mutate()}>{t("common.delete")}</Button>
      </td>
    </tr>
  );
}

function UserList({ accountId, o, onStarted }: { accountId: string; o: Overview; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [form, setForm] = useState({ name: "", password: "" });
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/database-users", { params: { path: { id: accountId } }, body: form })),
    onSuccess: (r) => { setForm({ name: "", password: "" }); onStarted(r); },
  });
  return (
    <Card className="overflow-x-auto p-0">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
        <CardTitle>{t("databases.users")}</CardTitle>
        <Usage used={o.users.length} max={o.max_users} />
      </div>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["databases.name", "databases.access", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
        </thead>
        <tbody>
          {o.users.map((u) => <UserRow key={u.id} u={u} o={o} onStarted={onStarted} />)}
          {o.users.length === 0 && <tr><td colSpan={3} className="px-4 py-6 text-center text-slate-500">{t("databases.noUsers")}</td></tr>}
        </tbody>
      </table>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="flex flex-wrap items-center gap-2 border-t border-slate-100 p-4 text-sm dark:border-slate-800">
        <label htmlFor="new-user" className="text-slate-500">{o.prefix}</label>
        <Input id="new-user" className="max-w-xs" required placeholder={t("databases.newUser")} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <Input aria-label={t("databases.password")} className="max-w-xs" required autoComplete="new-password" placeholder={t("databases.password")}
          value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <Button type="button" variant="ghost" onClick={() => setForm({ ...form, password: generatePassword() })}>{t("databases.generate")}</Button>
        <Button type="submit" variant="secondary" disabled={create.isPending}>{t("databases.createUser")}</Button>
        <div className="w-full"><ErrorAlert error={create.error} /></div>
      </form>
    </Card>
  );
}

function UserRow({ u, o, onStarted }: { u: DBUser; o: Overview; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const path = { params: { path: { id: u.id } } };
  const setPw = useMutation({
    mutationFn: () => unwrap(api.PUT("/database-users/{id}/password", { ...path, body: { password } })),
    onSuccess: (r) => { setPassword(""); onStarted(r); },
  });
  const remove = useMutation({ mutationFn: () => unwrap(api.DELETE("/database-users/{id}", path)), onSuccess: onStarted });
  const revoke = useMutation({
    mutationFn: (dbId: string) => unwrap(api.DELETE("/database-users/{id}/grants/{database_id}", { params: { path: { id: u.id, database_id: dbId } } })),
    onSuccess: onStarted,
  });
  return (
    <>
      <tr className="border-t border-slate-100 align-top dark:border-slate-800">
        <td className="px-4 py-3 font-medium">{u.name}</td>
        <td className="px-4 py-3">
          {u.databases.map((d) => (
            <div key={d.id} className="flex items-center gap-2">
              <span>{d.name}</span>
              <span className="text-xs text-slate-500">{d.privileges.includes("ALL") ? t("databases.all") : d.privileges.join(", ")}</span>
              <button type="button" className="text-xs text-red-700 hover:underline dark:text-red-400" onClick={() => revoke.mutate(d.id)}>{t("databases.revoke")}</button>
            </div>
          ))}
          {u.databases.length === 0 && <span className="text-slate-500">{t("databases.noAccess")}</span>}
        </td>
        <td className="whitespace-nowrap px-4 py-3 text-right">
          <Button variant="ghost" onClick={() => setOpen(!open)}>{open ? t("common.cancel") : t("databases.manage")}</Button>
          <Button variant="ghost" disabled={remove.isPending}
            onClick={() => window.confirm(t("databases.confirmDeleteUser", { name: u.name })) && remove.mutate()}>{t("common.delete")}</Button>
        </td>
      </tr>
      {open && (
        <tr className="bg-slate-50 dark:bg-slate-900/50">
          <td colSpan={3} className="space-y-4 px-4 py-4">
            <ErrorAlert error={setPw.error ?? remove.error ?? revoke.error} />
            <GrantForm u={u} o={o} onStarted={onStarted} />
            <form onSubmit={(e) => { e.preventDefault(); setPw.mutate(); }} className="flex flex-wrap items-end gap-2">
              <Field id={`pw-${u.id}`} label={t("databases.newPassword")}>
                <Input id={`pw-${u.id}`} required autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
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

/** Gives a user all or some privileges on one of the account's databases. */
function GrantForm({ u, o, onStarted }: { u: DBUser; o: Overview; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [dbId, setDbId] = useState(o.databases[0]?.id ?? "");
  const [all, setAll] = useState(true);
  const [privs, setPrivs] = useState<string[]>(["SELECT"]);
  const grant = useMutation({
    mutationFn: () => unwrap(api.PUT("/database-users/{id}/grants/{database_id}", {
      params: { path: { id: u.id, database_id: dbId } }, body: { privileges: all ? ["ALL"] : privs },
    })),
    onSuccess: onStarted,
  });
  if (o.databases.length === 0) return <p className="text-sm text-slate-500">{t("databases.noDatabases")}</p>;
  return (
    <form onSubmit={(e) => { e.preventDefault(); grant.mutate(); }} className="space-y-3">
      <p className="text-sm font-medium">{t("databases.grant")}</p>
      <div className="flex flex-wrap items-center gap-4 text-sm">
        <select aria-label={t("databases.database")} className={selectClass} value={dbId} onChange={(e) => setDbId(e.target.value)}>
          {o.databases.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
        </select>
        <label className="flex items-center gap-2"><input type="radio" checked={all} onChange={() => setAll(true)} /> {t("databases.all")}</label>
        <label className="flex items-center gap-2"><input type="radio" checked={!all} onChange={() => setAll(false)} /> {t("databases.some")}</label>
      </div>
      {!all && (
        <div className="grid gap-1 text-xs sm:grid-cols-3 lg:grid-cols-4">
          {o.privileges.map((p) => (
            <label key={p} className="flex items-center gap-2">
              <input type="checkbox" checked={privs.includes(p)} onChange={(e) => setPrivs(e.target.checked ? [...privs, p] : privs.filter((x) => x !== p))} /> {p}
            </label>
          ))}
        </div>
      )}
      <ErrorAlert error={grant.error} />
      <Button type="submit" variant="secondary" disabled={grant.isPending || (!all && privs.length === 0)}>{t("databases.saveGrant")}</Button>
    </form>
  );
}

/** The database server for admins (ADM-DB-08, 09). */
function ServerCard() {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const status = useQuery({ queryKey: ["mysql-status"], queryFn: () => unwrap(api.GET("/server/mysql")), retry: false });
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/server/mysql/root-password", { body: { password } })),
    onSuccess: () => setPassword(""),
  });
  if (status.isPending) return <Spinner />;
  if (!status.data) return <ErrorAlert error={status.error} />;
  const s = status.data;
  return (
    <Card>
      <CardTitle>{t("databases.server")}</CardTitle>
      <dl className="mb-4 grid gap-2 text-sm sm:grid-cols-[12rem_1fr]">
        <dt className="text-slate-500">{t("databases.mariadb")}</dt>
        <dd>{s.installed ? s.version || s.detail : t("databases.notInstalled")}</dd>
        <dt className="text-slate-500">{t("databases.phpmyadmin")}</dt>
        <dd>{s.phpmyadmin || t("databases.notInstalled")}</dd>
      </dl>
      {s.detail && s.installed && <Alert kind="info">{s.detail}</Alert>}
      <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-3">
        <p className="text-sm text-slate-500">{t("databases.rootHint")}</p>
        <div className="flex flex-wrap items-end gap-2">
          <Field id="root-pw" label={t("databases.rootPassword")}>
            <Input id="root-pw" required autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <Button type="button" variant="ghost" onClick={() => setPassword(generatePassword())}>{t("databases.generate")}</Button>
          <Button type="submit" disabled={save.isPending || !s.installed}>{t("databases.setRoot")}</Button>
        </div>
        <ErrorAlert error={save.error} />
        {save.isSuccess && <Alert kind="success">{t("common.saved")}</Alert>}
      </form>
    </Card>
  );
}
