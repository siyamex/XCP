import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";

type Setup = components["schemas"]["ServerSetup"];
type SettingItem = components["schemas"]["SettingItem"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

/** Server settings for admins: setup, global settings, updates, reboot (ADM-SRV-01, 02, 05, 06, 08). */
export function SettingsPage() {
  const { t } = useTranslation();
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("settings.title")}</h1>
      <SetupCard />
      <GlobalSettings />
      <UpdatesCard />
      <PowerCard />
    </div>
  );
}

function SetupCard() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["server-setup"], queryFn: () => unwrap(api.GET("/server/setup")), retry: false });
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  return <SetupForm initial={q.data} title={t(q.data.completed ? "settings.setup" : "settings.setupFirst")} />;
}

function SetupForm({ initial, title }: { initial: Setup; title: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [f, setF] = useState({
    hostname: initial.hostname, admin_email: initial.admin_email, timezone: initial.timezone,
    nameservers: initial.nameservers.join(", "), ipv4: initial.ipv4, ipv6: initial.ipv6,
  });
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/server/setup", {
      body: { ...f, nameservers: f.nameservers.split(/[\s,]+/).filter(Boolean) },
    })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["server-setup"] }),
  });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const hostChanged = f.hostname !== initial.hostname;
  return (
    <Card>
      <CardTitle>{title}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("settings.setupHint")}</p>
      <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <Field id="su-host" label={t("settings.hostname")}><Input id="su-host" value={f.hostname} onChange={set("hostname")} /></Field>
          <Field id="su-email" label={t("settings.adminEmail")}><Input id="su-email" type="email" value={f.admin_email} onChange={set("admin_email")} /></Field>
          <Field id="su-tz" label={t("settings.timezone")}><Input id="su-tz" placeholder="Europe/Berlin" value={f.timezone} onChange={set("timezone")} /></Field>
          <Field id="su-ns" label={t("settings.nameservers")}><Input id="su-ns" placeholder="ns1.example.com, ns2.example.com" value={f.nameservers} onChange={set("nameservers")} /></Field>
          <Field id="su-ip4" label={t("settings.ipv4")}><Input id="su-ip4" value={f.ipv4} onChange={set("ipv4")} /></Field>
          <Field id="su-ip6" label={t("settings.ipv6")}><Input id="su-ip6" value={f.ipv6} onChange={set("ipv6")} /></Field>
        </div>
        {hostChanged && <Alert kind="info">{t("settings.hostnameHint")}</Alert>}
        <ErrorAlert error={save.error} />
        {save.isSuccess && <Alert kind="success">{t("common.saved")} {hostChanged ? <Link to="/ssl" className="underline">{t("settings.runAutoSsl")}</Link> : null}</Alert>}
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
      </form>
    </Card>
  );
}

function GlobalSettings() {
  const q = useQuery({ queryKey: ["server-settings"], queryFn: () => unwrap(api.GET("/server/settings")), retry: false });
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  return <SettingsForm items={q.data.items} />;
}

const name = (key: string) => key.replace(/\./g, "_");

function SettingsForm({ items }: { items: SettingItem[] }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [search, setSearch] = useState("");
  const [edits, setEdits] = useState<Record<string, unknown>>({});
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/server/settings", { body: { values: edits } })),
    onSuccess: () => { setEdits({}); void qc.invalidateQueries({ queryKey: ["server-settings"] }); },
  });
  const q = search.trim().toLowerCase();
  const shown = items.filter((i) => !q || `${i.key} ${t(`settings.names.${name(i.key)}`)} ${t(`settings.hints.${name(i.key)}`)} ${t(`settings.groups.${i.group}`)}`.toLowerCase().includes(q));
  const valueOf = (i: SettingItem) => (i.key in edits ? edits[i.key] : i.value);
  return (
    <Card>
      <CardTitle>{t("settings.global")}</CardTitle>
      <Input aria-label={t("settings.search")} className="mb-4 max-w-sm" placeholder={t("settings.search")} value={search} onChange={(e) => setSearch(e.target.value)} />
      <div className="divide-y divide-slate-100 dark:divide-slate-800">
        {shown.map((i) => (
          <div key={i.key} className="grid items-center gap-2 py-3 md:grid-cols-[1fr_16rem]">
            <div>
              <label htmlFor={`s-${i.key}`} className="font-medium">{t(`settings.names.${name(i.key)}`)}</label>
              <span className="ml-2 text-xs text-slate-500">{t(`settings.groups.${i.group}`)}</span>
              <p className="text-xs text-slate-500">{t(`settings.hints.${name(i.key)}`)}</p>
            </div>
            {i.type === "bool" ? (
              <input id={`s-${i.key}`} type="checkbox" checked={valueOf(i) === true} onChange={(e) => setEdits({ ...edits, [i.key]: e.target.checked })} />
            ) : i.type === "enum" ? (
              <select id={`s-${i.key}`} className={selectClass} value={String(valueOf(i))} onChange={(e) => setEdits({ ...edits, [i.key]: e.target.value })}>
                {i.options.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
            ) : i.type === "int" ? (
              <Input id={`s-${i.key}`} type="number" min={i.min} max={i.max} value={Number(valueOf(i))} onChange={(e) => setEdits({ ...edits, [i.key]: Number(e.target.value) })} />
            ) : (
              <Input id={`s-${i.key}`} value={String(valueOf(i) ?? "")} onChange={(e) => setEdits({ ...edits, [i.key]: e.target.value })} />
            )}
          </div>
        ))}
        {shown.length === 0 && <p className="py-4 text-center text-sm text-slate-500">{t("settings.noMatch")}</p>}
      </div>
      <ErrorAlert error={save.error} />
      {save.isSuccess && <Alert kind="success">{t("common.saved")}</Alert>}
      <div className="mt-4"><Button disabled={save.isPending || Object.keys(edits).length === 0} onClick={() => save.mutate()}>{t("common.save")}</Button></div>
    </Card>
  );
}

function UpdatesCard() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["server-updates"], queryFn: () => unwrap(api.GET("/server/updates")), enabled: false, retry: false });
  const u = q.data;
  return (
    <Card>
      <CardTitle>{t("settings.updates")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("settings.updatesHint")}</p>
      <Button variant="secondary" disabled={q.isFetching} onClick={() => void q.refetch()}>{t("settings.checkUpdates")}</Button>
      <div className="mt-3 space-y-2 text-sm">
        <ErrorAlert error={q.error} />
        {u && (
          <>
            <p>{t("settings.currentVersion", { v: u.current })}{u.development && ` (${t("settings.devBuild")})`}</p>
            {u.error ? <Alert kind="info">{u.error}</Alert>
              : u.available ? <Alert kind="info">{t("settings.newVersion", { v: u.latest })} <a className="underline" href={u.url} target="_blank" rel="noreferrer">{t("settings.releaseNotes")}</a></Alert>
                : <p className="text-green-700 dark:text-green-400">{u.development ? t("settings.latestIs", { v: u.latest }) : t("settings.upToDate")}</p>}
          </>
        )}
      </div>
    </Card>
  );
}

function PowerCard() {
  const { t } = useTranslation();
  const [mode, setMode] = useState<"graceful" | "forced">("graceful");
  const [password, setPassword] = useState("");
  const rebuild = useMutation({ mutationFn: () => unwrap(api.POST("/server/rebuild")) });
  const reboot = useMutation({
    mutationFn: () => unwrap(api.POST("/server/reboot", { body: { mode, password } })),
    onSuccess: () => setPassword(""),
  });
  return (
    <Card>
      <CardTitle>{t("settings.power")}</CardTitle>
      <div className="space-y-6">
        <div>
          <p className="mb-2 text-sm text-slate-500">{t("settings.rebuildHint")}</p>
          <Button variant="secondary" disabled={rebuild.isPending}
            onClick={() => window.confirm(t("settings.confirmRebuild")) && rebuild.mutate()}>{t("settings.rebuild")}</Button>
          <ErrorAlert error={rebuild.error} />
          {rebuild.data && <Alert kind="success">{t("settings.rebuilding", { accounts: rebuild.data.queued.accounts ?? 0, zones: rebuild.data.queued.zones ?? 0 })}</Alert>}
        </div>
        <form onSubmit={(e) => { e.preventDefault(); window.confirm(t("settings.confirmReboot")) && reboot.mutate(); }} className="space-y-3">
          <p className="text-sm text-slate-500">{t("settings.rebootHint")}</p>
          <div className="flex flex-wrap items-end gap-3">
            <Field id="rb-mode" label={t("settings.rebootMode")}>
              <select id="rb-mode" className={selectClass} value={mode} onChange={(e) => setMode(e.target.value as "graceful" | "forced")}>
                <option value="graceful">{t("settings.graceful")}</option>
                <option value="forced">{t("settings.forced")}</option>
              </select>
            </Field>
            <Field id="rb-pw" label={t("settings.yourPassword")}>
              <Input id="rb-pw" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <Button type="submit" variant="secondary" disabled={reboot.isPending}>{t("settings.reboot")}</Button>
          </div>
          <ErrorAlert error={reboot.error} />
          {reboot.isSuccess && <Alert kind="info">{t("settings.rebooting")}</Alert>}
        </form>
      </div>
    </Card>
  );
}
