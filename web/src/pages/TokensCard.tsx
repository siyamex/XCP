import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Field, Input } from "../components/ui";

type NewToken = components["schemas"]["NewApiToken"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

/** The login's API tokens for scripts (ADR-0021). */
export function TokensCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["tokens"], queryFn: () => unwrap(api.GET("/me/tokens")) });
  const [name, setName] = useState("");
  const [scope, setScope] = useState<"read" | "write">("read");
  const [days, setDays] = useState("90");
  const [ips, setIps] = useState("");
  const [password, setPassword] = useState("");
  const [made, setMade] = useState<NewToken>();
  const refresh = () => void qc.invalidateQueries({ queryKey: ["tokens"] });
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/me/tokens", {
      body: { name, scope, expires_days: Number(days) || 0, ip_allow: ips.split(/[\s,]+/).filter(Boolean), password },
    })),
    onSuccess: (r) => { setMade(r); setName(""); setPassword(""); refresh(); },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/me/tokens/{id}", { params: { path: { id } } })),
    onSuccess: refresh,
  });
  return (
    <Card>
      <CardTitle>{t("security.tokens.title")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("security.tokens.hint")}</p>
      {made && (
        <Alert kind="success">
          <p>{t("security.tokens.made")}</p>
          <code className="mt-1 block break-all font-mono text-sm">{made.secret}</code>
        </Alert>
      )}
      <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="mb-4 grid gap-3 md:grid-cols-3">
        <Field id="tk-name" label={t("security.tokens.name")}><Input id="tk-name" required value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field id="tk-scope" label={t("security.tokens.scope")}>
          <select id="tk-scope" className={selectClass} value={scope} onChange={(e) => setScope(e.target.value as "read" | "write")}>
            <option value="read">{t("security.tokens.read")}</option>
            <option value="write">{t("security.tokens.write")}</option>
          </select>
        </Field>
        <Field id="tk-days" label={t("security.tokens.days")}><Input id="tk-days" inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} /></Field>
        <Field id="tk-ips" label={t("security.tokens.ips")}><Input id="tk-ips" placeholder="203.0.113.0/24" value={ips} onChange={(e) => setIps(e.target.value)} /></Field>
        <Field id="tk-pw" label={t("security.tokens.password")}><Input id="tk-pw" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        <div className="flex items-end"><Button type="submit" disabled={create.isPending}>{t("security.tokens.create")}</Button></div>
      </form>
      {(create.isError || revoke.isError || list.isError) && <ErrorAlert error={create.error ?? revoke.error ?? list.error} />}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-slate-500">
            <tr>
              {["name", "prefix", "scope", "expires", "lastUsed"].map((k) => <th key={k} className="py-2 pr-4 font-medium">{t(`security.tokens.col.${k}`)}</th>)}
              <th />
            </tr>
          </thead>
          <tbody>
            {list.data?.items.map((k) => (
              <tr key={k.id} className="border-t border-slate-200 dark:border-slate-800">
                <td className="py-2 pr-4">{k.name}</td>
                <td className="py-2 pr-4 font-mono">{k.prefix}</td>
                <td className="py-2 pr-4">{t(`security.tokens.${k.scope}`)}</td>
                <td className="py-2 pr-4">{k.expires_at ? new Date(k.expires_at).toLocaleDateString() : t("security.tokens.never")}</td>
                <td className="py-2 pr-4">{k.last_used_at ? `${new Date(k.last_used_at).toLocaleString()} (${k.last_used_ip})` : t("security.tokens.unused")}</td>
                <td className="py-2 text-right">
                  <Button variant="ghost" disabled={revoke.isPending} onClick={() => window.confirm(t("security.tokens.confirmRevoke", { name: k.name })) && revoke.mutate(k.id)}>{t("security.tokens.revoke")}</Button>
                </td>
              </tr>
            ))}
            {list.data?.items.length === 0 && <tr><td colSpan={6} className="py-4 text-slate-500">{t("security.tokens.none")}</td></tr>}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
