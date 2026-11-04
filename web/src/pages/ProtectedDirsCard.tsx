import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";

type Domain = components["schemas"]["Domain"];
type Settings = components["schemas"]["WebSettings"];

type UserRow = { name: string; password: string; existing: boolean };
type Dir = { path: string; realm: string; users: UserRow[] };

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

/** Folders of a site behind a user name and password (directory privacy). */
export function ProtectedDirsCard({ domains, onStarted }: { domains: Domain[]; onStarted: (r: { job_id?: string }) => void }) {
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
      <CardTitle>{t("domains.protected.title")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("domains.protected.hint")}</p>
      <Field id="pd-domain" label={t("domains.web.domain")}>
        <select id="pd-domain" className={selectClass} value={domain.id} onChange={(e) => setDomainId(e.target.value)}>
          {own.map((d) => <option key={d.id} value={d.id}>{d.display_name || d.name}</option>)}
        </select>
      </Field>
      {q.isPending && <Spinner />}
      {q.isError && <ErrorAlert error={q.error} />}
      {q.data && <DirsForm key={domain.id} domainId={domain.id} initial={q.data} onStarted={onStarted} />}
    </Card>
  );
}

function fromSettings(s: Settings): Dir[] {
  return s.protected_dirs.map((d) => ({ path: d.path, realm: d.realm, users: d.users.map((u) => ({ name: u.name, password: "", existing: true })) }));
}

function DirsForm({ domainId, initial, onStarted }: { domainId: string; initial: Settings; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [dirs, setDirs] = useState<Dir[]>(fromSettings(initial));
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/domains/{id}/protected-dirs", {
      params: { path: { id: domainId } },
      body: { dirs: dirs.map((d) => ({ path: d.path, realm: d.realm, users: d.users.map((u) => ({ name: u.name, ...(u.password ? { password: u.password } : {}) })) })) },
    })),
    onSuccess: (r) => { setDirs(fromSettings(r)); onStarted(r); },
  });
  const setDir = (i: number, d: Dir) => setDirs(dirs.map((x, j) => (j === i ? d : x)));
  return (
    <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="mt-4 space-y-4">
      {dirs.map((d, i) => (
        <div key={i} className="space-y-3 rounded-md border border-slate-200 p-3 dark:border-slate-800">
          <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
            <Field id={`pd-path-${i}`} label={t("domains.protected.folder")}><Input id={`pd-path-${i}`} required placeholder="/private" value={d.path} onChange={(e) => setDir(i, { ...d, path: e.target.value })} /></Field>
            <Field id={`pd-realm-${i}`} label={t("domains.protected.realm")}><Input id={`pd-realm-${i}`} placeholder="Restricted area" value={d.realm} onChange={(e) => setDir(i, { ...d, realm: e.target.value })} /></Field>
            <div className="flex items-end"><Button type="button" variant="ghost" onClick={() => setDirs(dirs.filter((_, j) => j !== i))}>{t("domains.protected.removeFolder")}</Button></div>
          </div>
          {d.users.map((u, k) => (
            <div key={k} className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
              <Field id={`pd-u-${i}-${k}`} label={t("domains.protected.user")}>
                <Input id={`pd-u-${i}-${k}`} required readOnly={u.existing} value={u.name} onChange={(e) => setDir(i, { ...d, users: d.users.map((x, j) => (j === k ? { ...x, name: e.target.value } : x)) })} />
              </Field>
              <Field id={`pd-p-${i}-${k}`} label={u.existing ? t("domains.protected.newPassword") : t("domains.protected.password")}>
                <Input id={`pd-p-${i}-${k}`} type="password" autoComplete="new-password" required={!u.existing} value={u.password} onChange={(e) => setDir(i, { ...d, users: d.users.map((x, j) => (j === k ? { ...x, password: e.target.value } : x)) })} />
              </Field>
              <div className="flex items-end"><Button type="button" variant="ghost" onClick={() => setDir(i, { ...d, users: d.users.filter((_, j) => j !== k) })}>{t("domains.protected.removeUser")}</Button></div>
            </div>
          ))}
          <Button type="button" variant="ghost" onClick={() => setDir(i, { ...d, users: [...d.users, { name: "", password: "", existing: false }] })}>{t("domains.protected.addUser")}</Button>
        </div>
      ))}
      {dirs.length === 0 && <p className="text-sm text-slate-500">{t("domains.protected.none")}</p>}
      <div className="flex gap-2">
        <Button type="button" variant="secondary" onClick={() => setDirs([...dirs, { path: "", realm: "", users: [] }])}>{t("domains.protected.addFolder")}</Button>
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
      </div>
      {save.isError && <ErrorAlert error={save.error} />}
      {save.isSuccess && <Alert kind="success">{t("domains.web.saved")}</Alert>}
    </form>
  );
}
