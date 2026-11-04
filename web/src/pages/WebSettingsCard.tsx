import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";

type Domain = components["schemas"]["Domain"];
type Settings = components["schemas"]["WebSettings"];

const ERROR_CODES = ["400", "401", "403", "404", "500", "502", "503"] as const;
const areaClass = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm dark:border-slate-700 dark:bg-slate-900";
const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

const lines = (s: string) => s.split(/[\s,]+/).filter(Boolean);

/** Per-domain web settings: error pages, hotlink protection, IP blocker, compression, caching (USR-WEB-04, 05, 08, 09). */
export function WebSettingsCard({ domains, onStarted }: { domains: Domain[]; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const own = domains.filter((d) => d.kind !== "alias");
  const [domainId, setDomainId] = useState("");
  const domain = own.find((d) => d.id === domainId) ?? own[0];
  const q = useQuery({
    queryKey: ["web-settings", domain?.id],
    queryFn: () => unwrap(api.GET("/domains/{id}/web", { params: { path: { id: domain!.id } } })),
    enabled: !!domain,
    retry: false,
  });
  if (!domain) return null;
  return (
    <Card>
      <CardTitle>{t("domains.web.title")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("domains.web.hint")}</p>
      <Field id="ws-domain" label={t("domains.web.domain")}>
        <select id="ws-domain" className={selectClass} value={domain.id} onChange={(e) => setDomainId(e.target.value)}>
          {own.map((d) => <option key={d.id} value={d.id}>{d.display_name || d.name}</option>)}
        </select>
      </Field>
      {q.isPending && <Spinner />}
      {q.isError && <ErrorAlert error={q.error} />}
      {q.data && <WebForm key={domain.id} domainId={domain.id} initial={q.data} onStarted={onStarted} />}
    </Card>
  );
}

function WebForm({ domainId, initial, onStarted }: { domainId: string; initial: Settings; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [pages, setPages] = useState<Record<string, string>>(Object.fromEntries(ERROR_CODES.map((c) => [c, initial.error_pages[c] ?? ""])));
  const [hot, setHot] = useState(initial.hotlink.enabled);
  const [hotHosts, setHotHosts] = useState(initial.hotlink.hosts.join(", "));
  const [hotExts, setHotExts] = useState(initial.hotlink.extensions.join(", "));
  const [hotEmpty, setHotEmpty] = useState(initial.hotlink.allow_empty);
  const [blocked, setBlocked] = useState(initial.blocked.join("\n"));
  const [compress, setCompress] = useState(initial.compress);
  const [cache, setCache] = useState(initial.cache_rules.map((r) => `${r.extensions.join(",")} ${r.days}`).join("\n"));
  const save = useMutation({
    mutationFn: () => {
      const cache_rules = cache.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
        const parts = l.split(/\s+/);
        return { extensions: lines(parts[0] ?? ""), days: Number(parts[1] ?? 0) };
      });
      const error_pages = Object.fromEntries(Object.entries(pages).filter(([, v]) => v.trim() !== ""));
      return unwrap(api.PUT("/domains/{id}/web", {
        params: { path: { id: domainId } },
        body: {
          error_pages, blocked: lines(blocked), compress, cache_rules,
          hotlink: { enabled: hot, hosts: lines(hotHosts), extensions: lines(hotExts), allow_empty: hotEmpty },
        },
      }));
    },
    onSuccess: onStarted,
  });
  return (
    <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="mt-4 space-y-5">
      <fieldset className="space-y-2">
        <legend className="text-sm font-semibold">{t("domains.web.errorPages")}</legend>
        <p className="text-sm text-slate-500">{t("domains.web.errorPagesHint")}</p>
        <div className="grid gap-3 md:grid-cols-2">
          {ERROR_CODES.map((c) => (
            <Field key={c} id={`ws-e-${c}`} label={c}>
              <Input id={`ws-e-${c}`} placeholder={`/errors/${c}.html`} value={pages[c] ?? ""} onChange={(e) => setPages({ ...pages, [c]: e.target.value })} />
            </Field>
          ))}
        </div>
      </fieldset>
      <fieldset className="space-y-2">
        <legend className="text-sm font-semibold">{t("domains.web.hotlink")}</legend>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={hot} onChange={(e) => setHot(e.target.checked)} />{t("domains.web.hotlinkOn")}</label>
        <div className="grid gap-3 md:grid-cols-2">
          <Field id="ws-hexts" label={t("domains.web.hotlinkTypes")}><Input id="ws-hexts" placeholder="jpg, png, gif, mp4" value={hotExts} onChange={(e) => setHotExts(e.target.value)} /></Field>
          <Field id="ws-hhosts" label={t("domains.web.hotlinkSites")}><Input id="ws-hhosts" placeholder="partner.example" value={hotHosts} onChange={(e) => setHotHosts(e.target.value)} /></Field>
        </div>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={hotEmpty} onChange={(e) => setHotEmpty(e.target.checked)} />{t("domains.web.hotlinkEmpty")}</label>
      </fieldset>
      <Field id="ws-blocked" label={t("domains.web.blocked")}>
        <textarea id="ws-blocked" rows={3} className={areaClass} placeholder="203.0.113.7&#10;198.51.100.0/24" value={blocked} onChange={(e) => setBlocked(e.target.value)} />
      </Field>
      <fieldset className="space-y-2">
        <legend className="text-sm font-semibold">{t("domains.web.speed")}</legend>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={compress} onChange={(e) => setCompress(e.target.checked)} />{t("domains.web.compress")}</label>
        <Field id="ws-cache" label={t("domains.web.cache")}>
          <textarea id="ws-cache" rows={3} className={areaClass} placeholder="css,js 30&#10;jpg,png,gif 90" value={cache} onChange={(e) => setCache(e.target.value)} />
        </Field>
      </fieldset>
      {save.isError && <ErrorAlert error={save.error} />}
      {save.isSuccess && <Alert kind="success">{t("domains.web.saved")}</Alert>}
      <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
    </form>
  );
}
