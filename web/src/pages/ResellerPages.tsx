import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";

type Reseller = components["schemas"]["Reseller"];
type Limits = components["schemas"]["ResellerLimits"];

const num = (s: string): number | null => (s.trim() === "" ? null : Number(s));
const show = (n: number | null | undefined, unit = "") => (n == null ? "∞" : `${n.toLocaleString()}${unit}`);

/** A bar of what has been given out against a cap, red when over it. */
function Meter({ label, used, cap, unlimited, oversell, unit }: { label: string; used: number; cap: number | null; unlimited?: boolean; oversell?: boolean; unit: string }) {
  const { t } = useTranslation();
  const over = cap != null && (used > cap || !!unlimited);
  const pct = cap == null || cap === 0 ? 0 : Math.min(100, (used / cap) * 100);
  return (
    <div>
      <div className="flex justify-between text-sm">
        <span>{label}</span>
        <span className={over ? "font-medium text-red-700 dark:text-red-400" : ""}>
          {unlimited ? t("resellers.someUnlimited") + " / " : `${used.toLocaleString()}${unit} / `}{show(cap, unit)}
        </span>
      </div>
      <div className="mt-1 h-2 overflow-hidden rounded bg-slate-200 dark:bg-slate-800">
        <div className={`h-full ${over ? "bg-red-500" : "bg-blue-600"}`} style={{ width: `${over ? 100 : pct}%` }} />
      </div>
      {over && oversell && <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">{t("resellers.oversold")}</p>}
    </div>
  );
}

function UsageMeters({ r }: { r: Reseller }) {
  const { t } = useTranslation();
  return (
    <div className="space-y-3">
      <Meter label={t("resellers.accounts")} used={r.usage.accounts} cap={r.limits.max_accounts} unit="" />
      <Meter label={t("resellers.disk")} used={r.usage.disk_mb} cap={r.limits.disk_mb} unlimited={r.usage.disk_unlimited} oversell={r.limits.oversell_disk} unit=" MB" />
      <Meter label={t("resellers.bandwidth")} used={r.usage.bandwidth_mb} cap={r.limits.bandwidth_mb} unlimited={r.usage.bandwidth_unlimited} oversell={r.limits.oversell_bandwidth} unit=" MB" />
      <p className="text-sm text-slate-500">{t("resellers.counts", { active: r.usage.active, suspended: r.usage.suspended })}</p>
    </div>
  );
}

/** A reseller's own dashboard: limits against what its packages give out (RSL-USE-01). */
export function ResellerDashboard() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["reseller-overview"], queryFn: () => unwrap(api.GET("/reseller/overview")), retry: false });
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  return (
    <Card>
      <CardTitle>{t("resellers.yourUsage")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("resellers.yourHint")}</p>
      <UsageMeters r={q.data} />
    </Card>
  );
}

/** Resellers for admins (ADM-RSL-01, 02). */
export function ResellersPage() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["resellers"], queryFn: () => unwrap(api.GET("/resellers")), retry: false });
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("resellers.title")}</h1>
      <NewReseller />
      {q.isPending && <Spinner />}
      {q.isError && <ErrorAlert error={q.error} />}
      {q.data?.items.map((r) => <ResellerCard key={r.id} r={r} />)}
      {q.data?.items.length === 0 && <p className="text-sm text-slate-500">{t("resellers.none")}</p>}
    </div>
  );
}

function LimitFields({ f, set }: { f: { max: string; disk: string; bw: string; osd: boolean; osb: boolean }; set: (v: { max: string; disk: string; bw: string; osd: boolean; osb: boolean }) => void }) {
  const { t } = useTranslation();
  return (
    <>
      <div className="grid gap-3 md:grid-cols-3">
        <Field id="rl-max" label={t("resellers.maxAccounts")}><Input id="rl-max" inputMode="numeric" placeholder="∞" value={f.max} onChange={(e) => set({ ...f, max: e.target.value })} /></Field>
        <Field id="rl-disk" label={t("resellers.diskCap")}><Input id="rl-disk" inputMode="numeric" placeholder="∞" value={f.disk} onChange={(e) => set({ ...f, disk: e.target.value })} /></Field>
        <Field id="rl-bw" label={t("resellers.bandwidthCap")}><Input id="rl-bw" inputMode="numeric" placeholder="∞" value={f.bw} onChange={(e) => set({ ...f, bw: e.target.value })} /></Field>
      </div>
      <div className="flex flex-wrap gap-4 text-sm">
        <label className="flex items-center gap-2"><input type="checkbox" checked={f.osd} onChange={(e) => set({ ...f, osd: e.target.checked })} />{t("resellers.oversellDisk")}</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={f.osb} onChange={(e) => set({ ...f, osb: e.target.checked })} />{t("resellers.oversellBandwidth")}</label>
      </div>
    </>
  );
}

const toLimits = (f: { max: string; disk: string; bw: string; osd: boolean; osb: boolean }): Limits => ({
  max_accounts: num(f.max), disk_mb: num(f.disk), bandwidth_mb: num(f.bw), oversell_disk: f.osd, oversell_bandwidth: f.osb,
});

function NewReseller() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [f, setF] = useState({ max: "", disk: "", bw: "", osd: false, osb: false });
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/resellers", { body: { username: name, email, password, limits: toLimits(f) } })),
    onSuccess: () => { setName(""); setEmail(""); setPassword(""); void qc.invalidateQueries({ queryKey: ["resellers"] }); },
  });
  return (
    <Card>
      <CardTitle>{t("resellers.new")}</CardTitle>
      <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="space-y-3">
        <div className="grid gap-3 md:grid-cols-3">
          <Field id="nr-name" label={t("resellers.username")}><Input id="nr-name" required value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field id="nr-email" label={t("resellers.email")}><Input id="nr-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
          <Field id="nr-pw" label={t("resellers.password")}><Input id="nr-pw" type="password" required autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        </div>
        <LimitFields f={f} set={setF} />
        {create.isError && <ErrorAlert error={create.error} />}
        <Button type="submit" disabled={create.isPending}>{t("resellers.create")}</Button>
      </form>
    </Card>
  );
}

function ResellerCard({ r }: { r: Reseller }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [f, setF] = useState({
    max: r.limits.max_accounts?.toString() ?? "", disk: r.limits.disk_mb?.toString() ?? "", bw: r.limits.bandwidth_mb?.toString() ?? "",
    osd: r.limits.oversell_disk, osb: r.limits.oversell_bandwidth,
  });
  const done = () => void qc.invalidateQueries({ queryKey: ["resellers"] });
  const save = useMutation({ mutationFn: () => unwrap(api.PUT("/resellers/{id}/limits", { params: { path: { id: r.id } }, body: toLimits(f) })), onSuccess: done });
  const suspended = r.status === "suspended";
  const toggle = useMutation({
    mutationFn: () => unwrap(api.POST(suspended ? "/resellers/{id}/unsuspend" : "/resellers/{id}/suspend", { params: { path: { id: r.id } } })),
    onSuccess: done,
  });
  return (
    <Card>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <CardTitle>{r.username}{suspended && <span className="ml-2 text-sm font-normal text-red-700 dark:text-red-400">{t("resellers.suspended")}</span>}</CardTitle>
        <Button variant="ghost" disabled={toggle.isPending} onClick={() => toggle.mutate()}>{t(suspended ? "resellers.unsuspend" : "resellers.suspend")}</Button>
      </div>
      <p className="mb-3 text-sm text-slate-500">{r.email || t("resellers.noEmail")}</p>
      <UsageMeters r={r} />
      <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="mt-4 space-y-3">
        <LimitFields f={f} set={setF} />
        {(save.isError || toggle.isError) && <ErrorAlert error={save.error ?? toggle.error} />}
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
      </form>
    </Card>
  );
}
