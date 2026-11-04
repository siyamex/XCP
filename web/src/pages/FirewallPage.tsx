import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";

type Config = components["schemas"]["FirewallConfig"];
type Overview = components["schemas"]["FirewallOverview"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";
const areaClass = `${selectClass} w-full font-mono`;
const SERVICES = ["panel", "ssh", "ftp"] as const;
const SOURCES = ["ssh", "mail", "ftp", "panel"] as const;

/** One entry per line: "value # comment". */
const entriesToText = (l: { cidr: string; comment: string }[]) => l.map((e) => (e.comment ? `${e.cidr} # ${e.comment}` : e.cidr)).join("\n");
const textToEntries = (s: string) =>
  s.split("\n").map((x) => x.trim()).filter(Boolean).map((x) => {
    const [cidr = "", ...c] = x.split("#");
    return { cidr: cidr.trim(), comment: c.join("#").trim() };
  });
const portsToText = (l: Config["ports"]) => l.map((p) => (p.comment ? `${p.port}/${p.proto} # ${p.comment}` : `${p.port}/${p.proto}`)).join("\n");
const textToPorts = (s: string): Config["ports"] =>
  s.split("\n").map((x) => x.trim()).filter(Boolean).map((x) => {
    const [spec = "", ...c] = x.split("#");
    const [port = "", proto] = spec.trim().split("/");
    return { port, proto: proto === "udp" ? "udp" : "tcp", comment: c.join("#").trim() };
  });
const words = (s: string) => s.split(/[\s,]+/).filter(Boolean);

/** Firewall, brute-force protection and IP access control for admins (ADM-SEC-01..03). */
export function FirewallPage() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["firewall"], queryFn: () => unwrap(api.GET("/server/firewall")), retry: false });
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("firewall.title")}</h1>
      <ConfigCard o={q.data} />
      <BansCard o={q.data} />
    </div>
  );
}

function ConfigCard({ o }: { o: Overview }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const c = o.config;
  const [f, setF] = useState({
    enabled: c.enabled, policy: c.policy, ssh_port: String(c.ssh_port),
    ports: portsToText(c.ports), allow: entriesToText(c.allow), deny: entriesToText(c.deny),
    restrict: Object.fromEntries(SERVICES.map((s) => [s, (c.restrict[s] ?? []).join(", ")])),
    rate: c.rate_limit.enabled, perMinute: String(c.rate_limit.per_minute), ratePorts: c.rate_limit.ports.join(", "),
    brute: c.brute.enabled, threshold: String(c.brute.threshold), window: String(c.brute.window_minutes),
    banMinutes: String(c.brute.ban_minutes), permanentAfter: String(c.brute.permanent_after), sources: c.brute.sources,
  });
  const save = useMutation({
    mutationFn: () => {
      const body: Config = {
        enabled: f.enabled, policy: f.policy, ssh_port: Number(f.ssh_port),
        ports: textToPorts(f.ports), allow: textToEntries(f.allow), deny: textToEntries(f.deny),
        restrict: Object.fromEntries(SERVICES.map((s) => [s, words(f.restrict[s] ?? "")] as const).filter(([, v]) => v.length > 0)),
        rate_limit: { enabled: f.rate, per_minute: Number(f.perMinute), ports: words(f.ratePorts) },
        brute: {
          enabled: f.brute, threshold: Number(f.threshold), window_minutes: Number(f.window),
          ban_minutes: Number(f.banMinutes), permanent_after: Number(f.permanentAfter), sources: f.sources,
        },
      };
      return unwrap(api.PUT("/server/firewall", { body }));
    },
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["firewall"] }),
  });
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF({ ...f, [k]: v });
  const text = (k: "ssh_port" | "perMinute" | "ratePorts" | "threshold" | "window" | "banMinutes" | "permanentAfter") => (e: React.ChangeEvent<HTMLInputElement>) => set(k, e.target.value);
  const toggleSource = (s: (typeof SOURCES)[number]) => set("sources", f.sources.includes(s) ? f.sources.filter((x) => x !== s) : [...f.sources, s]);
  return (
    <Card>
      <CardTitle>{t("firewall.rules")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("firewall.hint", { ip: o.your_ip, port: o.panel_port })}</p>
      <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-4">
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />{t("firewall.enabled")}</label>
        <div className="grid gap-4 md:grid-cols-2">
          <Field id="fw-policy" label={t("firewall.policy")}>
            <select id="fw-policy" className={selectClass} value={f.policy} onChange={(e) => set("policy", e.target.value as Config["policy"])}>
              <option value="open">{t("firewall.policyOpen")}</option>
              <option value="closed">{t("firewall.policyClosed")}</option>
            </select>
          </Field>
          <Field id="fw-ssh" label={t("firewall.sshPort")}><Input id="fw-ssh" inputMode="numeric" value={f.ssh_port} onChange={text("ssh_port")} /></Field>
        </div>
        <Field id="fw-ports" label={t("firewall.ports")}><textarea id="fw-ports" rows={4} className={areaClass} value={f.ports} onChange={(e) => set("ports", e.target.value)} /></Field>
        <div className="grid gap-4 md:grid-cols-2">
          <Field id="fw-allow" label={t("firewall.allow")}><textarea id="fw-allow" rows={4} className={areaClass} value={f.allow} onChange={(e) => set("allow", e.target.value)} /></Field>
          <Field id="fw-deny" label={t("firewall.deny")}><textarea id="fw-deny" rows={4} className={areaClass} value={f.deny} onChange={(e) => set("deny", e.target.value)} /></Field>
        </div>
        <fieldset className="space-y-3">
          <legend className="text-sm font-semibold">{t("firewall.restrict")}</legend>
          <p className="text-sm text-slate-500">{t("firewall.restrictHint")}</p>
          <div className="grid gap-4 md:grid-cols-3">
            {SERVICES.map((s) => (
              <Field key={s} id={`fw-r-${s}`} label={t(`firewall.service.${s}`)}>
                <Input id={`fw-r-${s}`} placeholder="203.0.113.0/24, 2001:db8::/32" value={f.restrict[s]} onChange={(e) => set("restrict", { ...f.restrict, [s]: e.target.value })} />
              </Field>
            ))}
          </div>
        </fieldset>
        <fieldset className="space-y-3">
          <legend className="text-sm font-semibold">{t("firewall.rate")}</legend>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.rate} onChange={(e) => set("rate", e.target.checked)} />{t("firewall.rateEnabled")}</label>
          <div className="grid gap-4 md:grid-cols-2">
            <Field id="fw-rate" label={t("firewall.perMinute")}><Input id="fw-rate" inputMode="numeric" value={f.perMinute} onChange={text("perMinute")} /></Field>
            <Field id="fw-rports" label={t("firewall.ratePorts")}><Input id="fw-rports" value={f.ratePorts} onChange={text("ratePorts")} /></Field>
          </div>
        </fieldset>
        <fieldset className="space-y-3">
          <legend className="text-sm font-semibold">{t("firewall.brute")}</legend>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.brute} onChange={(e) => set("brute", e.target.checked)} />{t("firewall.bruteEnabled")}</label>
          <div className="grid gap-4 md:grid-cols-4">
            <Field id="fw-th" label={t("firewall.threshold")}><Input id="fw-th" inputMode="numeric" value={f.threshold} onChange={text("threshold")} /></Field>
            <Field id="fw-win" label={t("firewall.window")}><Input id="fw-win" inputMode="numeric" value={f.window} onChange={text("window")} /></Field>
            <Field id="fw-ban" label={t("firewall.banMinutes")}><Input id="fw-ban" inputMode="numeric" value={f.banMinutes} onChange={text("banMinutes")} /></Field>
            <Field id="fw-perm" label={t("firewall.permanentAfter")}><Input id="fw-perm" inputMode="numeric" value={f.permanentAfter} onChange={text("permanentAfter")} /></Field>
          </div>
          <div className="flex flex-wrap gap-4 text-sm">
            {SOURCES.map((s) => (
              <label key={s} className="flex items-center gap-2"><input type="checkbox" checked={f.sources.includes(s)} onChange={() => toggleSource(s)} />{t(`firewall.service.${s}`)}</label>
            ))}
          </div>
        </fieldset>
        {save.isError && <ErrorAlert error={save.error} />}
        {save.data?.added_your_ip && <Alert kind="info">{t("firewall.addedYourIp", { ip: o.your_ip })}</Alert>}
        {save.isSuccess && <Alert kind="success">{t("firewall.saved")}</Alert>}
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
      </form>
    </Card>
  );
}

function BansCard({ o }: { o: Overview }) {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const [ip, setIp] = useState("");
  const [minutes, setMinutes] = useState("0");
  const [reason, setReason] = useState("");
  const refresh = () => void qc.invalidateQueries({ queryKey: ["firewall"] });
  const ban = useMutation({
    mutationFn: () => unwrap(api.POST("/server/firewall/bans", { body: { ip: ip.trim(), minutes: Number(minutes), reason } })),
    onSuccess: () => { setIp(""); setReason(""); refresh(); },
  });
  const unban = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/server/firewall/bans/{id}", { params: { path: { id } } })),
    onSuccess: refresh,
  });
  const when = (s: string | null) => (s ? new Date(s).toLocaleString(i18n.language) : t("firewall.never"));
  return (
    <Card>
      <CardTitle>{t("firewall.bans")}</CardTitle>
      <form onSubmit={(e) => { e.preventDefault(); ban.mutate(); }} className="mb-4 grid gap-3 md:grid-cols-4">
        <Field id="b-ip" label={t("firewall.banIp")}><Input id="b-ip" required value={ip} onChange={(e) => setIp(e.target.value)} /></Field>
        <Field id="b-min" label={t("firewall.banFor")}><Input id="b-min" inputMode="numeric" value={minutes} onChange={(e) => setMinutes(e.target.value)} /></Field>
        <Field id="b-why" label={t("firewall.reason")}><Input id="b-why" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
        <div className="flex items-end"><Button type="submit" disabled={ban.isPending}>{t("firewall.ban")}</Button></div>
      </form>
      {(ban.isError || unban.isError) && <ErrorAlert error={ban.error ?? unban.error} />}
      <table className="w-full text-left text-sm">
        <thead><tr className="border-b border-slate-200 dark:border-slate-800">
          <th className="py-2">{t("firewall.banIp")}</th><th>{t("firewall.source")}</th><th>{t("firewall.reason")}</th><th>{t("firewall.since")}</th><th>{t("firewall.until")}</th><th />
        </tr></thead>
        <tbody>
          {o.history.map((b) => (
            <tr key={b.id} className={`border-b border-slate-100 dark:border-slate-900 ${b.active ? "" : "text-slate-400"}`}>
              <td className="py-2 font-mono">{b.ip}</td>
              <td>{t(`firewall.service.${b.source}`, { defaultValue: b.source })}</td>
              <td>{b.reason}</td>
              <td>{when(b.created_at)}</td>
              <td>{b.active ? when(b.expires_at) : t("firewall.lifted")}</td>
              <td className="text-right">{b.active && <Button type="button" onClick={() => unban.mutate(b.id)} disabled={unban.isPending}>{t("firewall.unban")}</Button>}</td>
            </tr>
          ))}
          {o.history.length === 0 && <tr><td colSpan={6} className="py-4 text-slate-500">{t("firewall.none")}</td></tr>}
        </tbody>
      </table>
    </Card>
  );
}
