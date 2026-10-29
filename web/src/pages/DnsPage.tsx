import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { cn } from "../lib/cn";

type Zone = components["schemas"]["Zone"];
type DNSRecord = components["schemas"]["Record"];
type RecordType = DNSRecord["type"];
type MailRouting = Zone["mail_routing"];
type Settings = components["schemas"]["DNSSettings"];

const selectClass = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";
const types: RecordType[] = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "TLSA", "HTTPS", "SVCB"];
// Types with separate fields in simple mode; the others take one value.
const composed: RecordType[] = ["MX", "SRV", "CAA"];

/** Zones: all of them for admins, the account's own for users. */
export function ZonesPage() {
  const { t } = useTranslation();
  const me = useMe();
  const [search, setSearch] = useState("");
  const isAdmin = me.data?.role === "admin";
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">{t("dns.title")}</h1>
        {isAdmin && <Link to="/dns/settings"><Button variant="secondary">{t("dns.settings.title")}</Button></Link>}
      </div>
      {isAdmin && <Input placeholder={t("dns.search")} value={search} onChange={(e) => setSearch(e.target.value)} className="max-w-sm" />}
      <ZoneList search={search} />
    </div>
  );
}

/** A list of zones with links to the editor; accountId limits it to one account. */
export function ZoneList({ accountId, search = "" }: { accountId?: string; search?: string }) {
  const { t } = useTranslation();
  const zones = useQuery({
    queryKey: ["zones", accountId ?? "", search],
    queryFn: () => unwrap(api.GET("/dns/zones", { params: { query: { account_id: accountId, search: search || undefined } } })),
    retry: false,
  });
  if (zones.isPending) return <Spinner />;
  if (!zones.data) return <ErrorAlert error={zones.error} />;
  return (
    <Card className="overflow-x-auto p-0">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr><th className="px-4 py-3 font-medium">{t("dns.zone")}</th>{!accountId && <th className="px-4 py-3 font-medium">{t("dns.account")}</th>}<th className="px-4 py-3 font-medium">{t("dns.changed")}</th></tr>
        </thead>
        <tbody>
          {zones.data.items.map((z) => (
            <tr key={z.id} className="border-t border-slate-100 dark:border-slate-800">
              <td className="px-4 py-3"><Link to="/dns/$zoneId" params={{ zoneId: z.id }} className="font-medium text-brand hover:underline">{z.display_name}</Link></td>
              {!accountId && <td className="px-4 py-3">{z.account}</td>}
              <td className="px-4 py-3">{new Date(z.updated_at).toLocaleString()}</td>
            </tr>
          ))}
          {zones.data.items.length === 0 && <tr><td colSpan={3} className="px-4 py-6 text-center text-slate-500">{t("dns.empty")}</td></tr>}
        </tbody>
      </table>
    </Card>
  );
}

/** The zone editor (USR-DNS-01..03). */
export function ZonePage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { zoneId = "" } = useParams({ strict: false }) as { zoneId?: string };
  const [jobId, setJobId] = useState<string>();
  const [editing, setEditing] = useState<DNSRecord>();
  const [saves, setSaves] = useState(0); // a new form after each saved change
  const zone = useQuery({ queryKey: ["zone", zoneId], queryFn: () => unwrap(api.GET("/dns/zones/{id}", { params: { path: { id: zoneId } } })), retry: false });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["zone", zoneId] });
  const started = (r: { job_id?: string }) => {
    setJobId(r.job_id);
    setEditing(undefined);
    setSaves((n) => n + 1);
    refresh();
  };
  const remove = useMutation({ mutationFn: (id: string) => unwrap(api.DELETE("/dns/records/{id}", { params: { path: { id } } })), onSuccess: started });

  if (zone.isPending) return <Spinner />;
  if (!zone.data) return <ErrorAlert error={zone.error} />;
  const z = zone.data;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">{z.display_name}</h1>
        <Link to="/dns"><Button variant="secondary">{t("common.back")}</Button></Link>
      </div>
      <JobNotice jobId={jobId} onDone={refresh} />
      {!z.serving && <Alert>{t("dns.notServing")}</Alert>}
      <Alert kind="info">{t("dns.nameserversHint", { names: (z.nameservers ?? []).join(", ") })}</Alert>
      <ErrorAlert error={remove.error} />
      <Card className="overflow-x-auto p-0">
        <div className="px-4 pt-4"><CardTitle>{t("dns.records")}</CardTitle></div>
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
            <tr>{["dns.name", "dns.type", "dns.ttl", "dns.value", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}</tr>
          </thead>
          <tbody>
            {(z.records ?? []).map((r) => (
              <tr key={r.id} className={cn("border-t border-slate-100 align-top dark:border-slate-800", editing?.id === r.id && "bg-brand/5")}>
                <td className="px-4 py-2 font-mono text-xs">{r.name}</td>
                <td className="px-4 py-2">{r.type}{r.managed && <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-300" title={t("dns.managedHint")}>{t("dns.managed")}</span>}</td>
                <td className="px-4 py-2">{r.ttl}</td>
                <td className="max-w-md break-all px-4 py-2 font-mono text-xs">{r.content}</td>
                <td className="whitespace-nowrap px-4 py-2 text-right">
                  <Button variant="ghost" onClick={() => setEditing(r)}>{t("common.edit")}</Button>
                  <Button variant="ghost" disabled={remove.isPending}
                    onClick={() => window.confirm(t("dns.confirmDelete", { name: r.name, type: r.type })) && remove.mutate(r.id)}>{t("common.delete")}</Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <RecordForm key={editing?.id ?? `new-${saves}`} zone={z} record={editing} onStarted={started} onCancel={() => setEditing(undefined)} />
      <MailRoutingCard zone={z} onSaved={refresh} />
    </div>
  );
}

function RecordForm({ zone, record, onStarted, onCancel }: { zone: Zone; record?: DNSRecord; onStarted: (r: { job_id?: string }) => void; onCancel: () => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState(record?.name ?? "");
  const [type, setType] = useState<RecordType>(record?.type ?? "A");
  const [ttl, setTtl] = useState(record ? String(record.ttl) : "");
  // Editing shows the raw value; simple mode composes MX, SRV and CAA from fields.
  const [advanced, setAdvanced] = useState(!!record);
  const [value, setValue] = useState(record?.content ?? "");
  const [parts, setParts] = useState({ priority: "10", weight: "5", port: "", flags: "0", tag: "issue" });
  const simple = !advanced && composed.includes(type);
  const content = !simple ? value
    : type === "MX" ? `${parts.priority} ${value}`
    : type === "SRV" ? `${parts.priority} ${parts.weight} ${parts.port} ${value}`
    : `${parts.flags} ${parts.tag} "${value}"`;
  const body = { name, type, ttl: ttl ? Number(ttl) : 0, content };
  const save = useMutation({
    mutationFn: () => record
      ? unwrap(api.PUT("/dns/records/{id}", { params: { path: { id: record.id } }, body }))
      : unwrap(api.POST("/dns/zones/{id}/records", { params: { path: { id: zone.id } }, body })),
    onSuccess: onStarted,
  });
  const set = (k: keyof typeof parts) => (e: { target: { value: string } }) => setParts({ ...parts, [k]: e.target.value });

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate();
  }

  return (
    <Card>
      <CardTitle>{record ? t("dns.editRecord") : t("dns.addRecord")}</CardTitle>
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4">
          <Field id="rec-name" label={t("dns.name")}>
            <Input id="rec-name" placeholder="@" value={name} onChange={(e) => setName(e.target.value)} />
            <p className="text-xs text-slate-500">{t("dns.nameHint", { zone: zone.name })}</p>
          </Field>
          <Field id="rec-type" label={t("dns.type")}>
            <select id="rec-type" className={selectClass} value={type} onChange={(e) => setType(e.target.value as RecordType)}>
              {types.map((ty) => <option key={ty} value={ty}>{ty}</option>)}
            </select>
          </Field>
          <Field id="rec-ttl" label={t("dns.ttl")}>
            <Input id="rec-ttl" type="number" min={60} max={604800} placeholder={t("dns.ttlDefault")} value={ttl} onChange={(e) => setTtl(e.target.value)} />
          </Field>
        </div>
        <div className="grid gap-4 md:grid-cols-4">
          {simple && (type === "MX" || type === "SRV") && (
            <Field id="rec-prio" label={t("dns.priority")}><Input id="rec-prio" type="number" min={0} max={65535} value={parts.priority} onChange={set("priority")} /></Field>
          )}
          {simple && type === "SRV" && <>
            <Field id="rec-weight" label={t("dns.weight")}><Input id="rec-weight" type="number" min={0} max={65535} value={parts.weight} onChange={set("weight")} /></Field>
            <Field id="rec-port" label={t("dns.port")}><Input id="rec-port" type="number" min={0} max={65535} required value={parts.port} onChange={set("port")} /></Field>
          </>}
          {simple && type === "CAA" && (
            <Field id="rec-tag" label={t("dns.caaTag")}>
              <select id="rec-tag" className={selectClass} value={parts.tag} onChange={set("tag")}>
                {["issue", "issuewild", "iodef"].map((tag) => <option key={tag} value={tag}>{tag}</option>)}
              </select>
            </Field>
          )}
          <div className={simple ? "md:col-span-2" : "md:col-span-4"}>
            <Field id="rec-value" label={simple ? t(`dns.valueFor.${type}`) : t("dns.value")}>
              <Input id="rec-value" required value={value} onChange={(e) => setValue(e.target.value)} placeholder={t(`dns.placeholders.${type}`)} />
              <p className="text-xs text-slate-500">{t(type === "TXT" ? "dns.txtHint" : "dns.valueHint")}</p>
            </Field>
          </div>
        </div>
        {composed.includes(type) && (
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={advanced} onChange={(e) => setAdvanced(e.target.checked)} /> {t("dns.advanced")}
          </label>
        )}
        <ErrorAlert error={save.error} />
        <div className="flex gap-2">
          <Button type="submit" disabled={save.isPending}>{record ? t("common.save") : t("dns.addRecord")}</Button>
          {record && <Button type="button" variant="secondary" onClick={onCancel}>{t("common.cancel")}</Button>}
        </div>
      </form>
    </Card>
  );
}

function MailRoutingCard({ zone, onSaved }: { zone: Zone; onSaved: () => void }) {
  const { t } = useTranslation();
  const [routing, setRouting] = useState<MailRouting>(zone.mail_routing);
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/dns/zones/{id}", { params: { path: { id: zone.id } }, body: { mail_routing: routing } })),
    onSuccess: onSaved,
  });
  return (
    <Card>
      <CardTitle>{t("dns.mail.title")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("dns.mail.help")}</p>
      <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-3">
        {(["auto", "local", "backup", "remote"] as const).map((r) => (
          <label key={r} className="flex items-start gap-2 text-sm">
            <input type="radio" name="mail-routing" className="mt-1" checked={routing === r} onChange={() => setRouting(r)} />
            <span><b>{t(`dns.mail.${r}`)}</b>{r === "auto" && zone.mail_routing_effective && <> — {t("dns.mail.detected", { routing: t(`dns.mail.${zone.mail_routing_effective}`) })}</>}</span>
          </label>
        ))}
        <ErrorAlert error={save.error} />
        {save.isSuccess && <Alert kind="success">{t("common.saved")}</Alert>}
        <Button type="submit" variant="secondary" disabled={save.isPending || routing === zone.mail_routing}>{t("common.save")}</Button>
      </form>
    </Card>
  );
}

/** Server DNS settings: name servers with a check, addresses, template (ADM-DNS-02/03). */
export function DnsSettingsPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const current = useQuery({ queryKey: ["dns-settings"], queryFn: () => unwrap(api.GET("/server/dns")), retry: false });
  const [form, setForm] = useState<Settings>();
  useEffect(() => {
    if (current.data && !form) {
      const { nameservers, ipv4, ipv6, ttl, template } = current.data;
      setForm({ nameservers: nameservers.length ? nameservers : ["", ""], ipv4, ipv6, ttl, template });
    }
  }, [current.data, form]);
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/server/dns", { body: { ...form!, nameservers: form!.nameservers.filter((n) => n.trim()) } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["dns-settings"] }),
  });
  if (current.isPending || !form) return current.error ? <ErrorAlert error={current.error} /> : <Spinner />;
  const v = current.data!;
  const setTpl = (i: number, k: "name" | "type" | "content", val: string) =>
    setForm({ ...form, template: form.template.map((r, j) => (j === i ? { ...r, [k]: val } : r)) });

  return (
    <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-2xl font-bold">{t("dns.settings.title")}</h1>
        <Link to="/dns"><Button type="button" variant="secondary">{t("common.back")}</Button></Link>
      </div>
      <ErrorAlert error={save.error} />
      {save.isSuccess && <Alert kind="success">{t("dns.settings.saved", { count: save.data.zones_queued })}</Alert>}

      <Card className="space-y-4">
        <CardTitle>{t("dns.settings.nameservers")}</CardTitle>
        <p className="text-sm text-slate-500">{t("dns.settings.nameserversHelp")}</p>
        {v.nameservers.length === 0 && <Alert kind="info">{t("dns.settings.noNameservers")}</Alert>}
        <div className="grid gap-3 md:grid-cols-2">
          {form.nameservers.map((ns, i) => (
            <Input key={i} aria-label={`NS ${i + 1}`} placeholder={`ns${i + 1}.example.com`} value={ns}
              onChange={(e) => setForm({ ...form, nameservers: form.nameservers.map((n, j) => (j === i ? e.target.value : n)) })} />
          ))}
        </div>
        <Button type="button" variant="ghost" onClick={() => setForm({ ...form, nameservers: [...form.nameservers, ""] })}>{t("dns.settings.addNameserver")}</Button>
        {v.report.length > 0 && (
          <ul className="space-y-1 text-sm">
            {v.report.map((c) => (
              <li key={c.name}>
                <span className={c.ok ? "text-green-700 dark:text-green-400" : "text-amber-700 dark:text-amber-400"}>{c.ok ? "✓" : "!"}</span>{" "}
                <b>{c.name}</b> {c.addresses.length > 0 && <code className="text-xs">{c.addresses.join(", ")}</code>} {c.problem && <span className="text-slate-500">— {c.problem}</span>}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card className="space-y-4">
        <CardTitle>{t("dns.settings.addresses")}</CardTitle>
        <p className="text-sm text-slate-500">{t("dns.settings.addressesHelp", { ips: v.detected_ips.join(", ") || "-" })}</p>
        <div className="grid gap-4 md:grid-cols-3">
          <Field id="ipv4" label="IPv4"><Input id="ipv4" value={form.ipv4} onChange={(e) => setForm({ ...form, ipv4: e.target.value })} /></Field>
          <Field id="ipv6" label="IPv6"><Input id="ipv6" value={form.ipv6} onChange={(e) => setForm({ ...form, ipv6: e.target.value })} /></Field>
          <Field id="ttl" label={t("dns.settings.ttl")}><Input id="ttl" type="number" min={60} max={604800} value={form.ttl} onChange={(e) => setForm({ ...form, ttl: Number(e.target.value) })} /></Field>
        </div>
      </Card>

      <Card className="space-y-3">
        <CardTitle>{t("dns.settings.template")}</CardTitle>
        <p className="text-sm text-slate-500">{t("dns.settings.templateHelp")}</p>
        {form.template.map((r, i) => (
          <div key={i} className="grid grid-cols-[1fr_7rem_2fr_auto] gap-2">
            <Input aria-label={t("dns.name")} value={r.name} onChange={(e) => setTpl(i, "name", e.target.value)} />
            <select aria-label={t("dns.type")} className={selectClass} value={r.type} onChange={(e) => setTpl(i, "type", e.target.value)}>
              {types.map((ty) => <option key={ty} value={ty}>{ty}</option>)}
            </select>
            <Input aria-label={t("dns.value")} value={r.content} onChange={(e) => setTpl(i, "content", e.target.value)} />
            <Button type="button" variant="ghost" onClick={() => setForm({ ...form, template: form.template.filter((_, j) => j !== i) })}>{t("common.delete")}</Button>
          </div>
        ))}
        <Button type="button" variant="ghost" onClick={() => setForm({ ...form, template: [...form.template, { name: "", type: "A", content: "" }] })}>{t("dns.settings.addTemplateRecord")}</Button>
      </Card>
      <Button type="submit" disabled={save.isPending}>{t("dns.settings.save")}</Button>
    </form>
  );
}
