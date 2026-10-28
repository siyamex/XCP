import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { cn } from "../lib/cn";

type Domain = components["schemas"]["Domain"];
type Redirect = components["schemas"]["Redirect"];
type Kind = components["schemas"]["DomainCreate"]["kind"];
type Canonical = Domain["canonical"];

const selectClass = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

const kindStyle: Record<Domain["kind"], string> = {
  primary: "bg-brand/10 text-brand",
  addon: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200",
  sub: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-200",
  alias: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
};

/** The Domains page of a user login: its own account's domains. */
export function MyDomainsPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("domains.title")}</h1>
      {me.data?.account_id ? <DomainsPanel accountId={me.data.account_id} /> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

/** Domains and redirects of one account: on the account page for admins and on a user's Domains page. */
export function DomainsPanel({ accountId }: { accountId: string }) {
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const path = { params: { path: { id: accountId } } };
  const domains = useQuery({ queryKey: ["domains", accountId], queryFn: () => unwrap(api.GET("/accounts/{id}/domains", path)), retry: false });
  // 403 when the package's feature list has no "redirects": the section is hidden then.
  const redirects = useQuery({ queryKey: ["redirects", accountId], queryFn: () => unwrap(api.GET("/accounts/{id}/redirects", path)), retry: false });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["domains", accountId] });
    void qc.invalidateQueries({ queryKey: ["redirects", accountId] });
  };
  const started = (r: { job_id?: string }) => {
    setJobId(r.job_id);
    refresh();
  };

  if (domains.isPending) return <Spinner />;
  if (!domains.data) return <ErrorAlert error={domains.error} />;
  const list = domains.data.items;
  return (
    <>
      <JobNotice jobId={jobId} onDone={refresh} />
      <DomainList domains={list} onStarted={started} />
      <AddDomain accountId={accountId} domains={list} onStarted={started} />
      {redirects.data && <Redirects domains={list} redirects={redirects.data.items} onStarted={started} />}
    </>
  );
}

function DomainList({ domains, onStarted }: { domains: Domain[]; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [editing, setEditing] = useState<string>();
  const remove = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/domains/{id}", { params: { path: { id } } })),
    onSuccess: onStarted,
  });
  return (
    <Card className="overflow-x-auto p-0">
      <div className="px-4 pt-4"><CardTitle>{t("domains.title")}</CardTitle></div>
      <div className="px-4"><ErrorAlert error={remove.error} /></div>
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["domains.name", "domains.kind", "domains.docroot", "domains.canonical", ""].map((k) => (
            <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>))}</tr>
        </thead>
        <tbody>
          {domains.map((d) => (
            <tr key={d.id} className="border-t border-slate-100 align-top dark:border-slate-800">
              <td className="px-4 py-3">
                {d.name.startsWith("*.") ? <span className="font-medium">{d.display_name}</span> : (
                  <a href={`http://${d.name}/`} target="_blank" rel="noreferrer" className="font-medium text-brand hover:underline">{d.display_name}</a>
                )}
              </td>
              <td className="px-4 py-3">
                <span className={cn("rounded px-2 py-0.5 text-xs font-medium", kindStyle[d.kind])}>{t(`domains.kinds.${d.kind}`)}</span>
                {d.parent_name && <span className="ml-2 text-xs text-slate-500">{t(d.kind === "alias" ? "domains.showsSite" : "domains.under", { name: d.parent_name })}</span>}
              </td>
              <td className="px-4 py-3">
                {editing === d.id ? <EditDomain domain={d} onDone={(r) => { setEditing(undefined); if (r) onStarted(r); }} /> : <code className="text-xs">~/{d.docroot}</code>}
              </td>
              <td className="px-4 py-3">{editing === d.id ? null : t(`domains.canonicals.${d.canonical || "both"}`)}</td>
              <td className="whitespace-nowrap px-4 py-3 text-right">
                {editing !== d.id && <Button variant="ghost" onClick={() => setEditing(d.id)}>{t("common.edit")}</Button>}
                {d.kind !== "primary" && editing !== d.id && (
                  <Button variant="ghost" disabled={remove.isPending}
                    onClick={() => window.confirm(t("domains.confirmDelete", { name: d.display_name })) && remove.mutate(d.id)}>
                    {t("common.delete")}
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function EditDomain({ domain, onDone }: { domain: Domain; onDone: (r?: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const alias = domain.kind === "alias";
  const [docroot, setDocroot] = useState(alias ? "" : domain.docroot);
  const [canonical, setCanonical] = useState<Canonical>(domain.canonical);
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/domains/{id}", { params: { path: { id: domain.id } }, body: { docroot, canonical } })),
    onSuccess: onDone,
  });
  return (
    <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="min-w-64 space-y-2">
      <ErrorAlert error={save.error} />
      {!alias && (
        <Field id={`docroot-${domain.id}`} label={t("domains.docroot")}>
          <Input id={`docroot-${domain.id}`} required value={docroot} onChange={(e) => setDocroot(e.target.value)} />
        </Field>
      )}
      {!domain.name.startsWith("*.") && (
        <Field id={`canonical-${domain.id}`} label={t("domains.canonical")}>
          <select id={`canonical-${domain.id}`} className={selectClass} value={canonical} onChange={(e) => setCanonical(e.target.value as Canonical)}>
            {(["", "www", "bare"] as const).map((c) => (
              <option key={c} value={c}>{t(`domains.canonicals.${c || "both"}`, { name: domain.name })}</option>
            ))}
          </select>
        </Field>
      )}
      <div className="flex gap-2">
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
        <Button type="button" variant="secondary" onClick={() => onDone()}>{t("common.cancel")}</Button>
      </div>
    </form>
  );
}

function AddDomain({ accountId, domains, onStarted }: { accountId: string; domains: Domain[]; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const parents = domains.filter((d) => d.kind === "primary" || d.kind === "addon");
  const [kind, setKind] = useState<Kind>("addon");
  const [name, setName] = useState("");
  const [parentId, setParentId] = useState("");
  const [docroot, setDocroot] = useState("");
  const parent = parents.find((d) => d.id === parentId) ?? parents[0];
  const fullName = kind === "sub" ? `${name || "…"}.${parent?.name ?? ""}` : name;
  const add = useMutation({
    mutationFn: () => unwrap(api.POST("/accounts/{id}/domains", {
      params: { path: { id: accountId } },
      body: { kind, name, parent_id: kind === "addon" ? undefined : parent?.id, docroot: kind === "alias" ? undefined : docroot },
    })),
    onSuccess: (d) => {
      setName("");
      setDocroot("");
      onStarted(d);
    },
  });
  const needsProof = add.error instanceof ApiError && add.error.code === "verification_required";
  const proof = useQuery({
    queryKey: ["domain-verification", accountId, name],
    queryFn: () => unwrap(api.GET("/accounts/{id}/domain-verification", { params: { path: { id: accountId }, query: { name } } })),
    enabled: needsProof,
    retry: false,
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    add.mutate();
  }

  return (
    <Card>
      <CardTitle>{t("domains.add")}</CardTitle>
      <form onSubmit={submit} className="space-y-4">
        <div className="flex flex-wrap gap-2" role="radiogroup" aria-label={t("domains.kind")}>
          {(["addon", "sub", "alias"] as const).map((k) => (
            <Button key={k} type="button" role="radio" aria-checked={kind === k} variant={kind === k ? "primary" : "secondary"}
              onClick={() => { setKind(k); add.reset(); }}>
              {t(`domains.kinds.${k}`)}
            </Button>
          ))}
        </div>
        <p className="text-sm text-slate-500">{t(`domains.help.${kind}`)}</p>
        <div className="grid gap-4 md:grid-cols-3">
          <Field id="dom-name" label={kind === "sub" ? t("domains.subName") : t("domains.name")}>
            <Input id="dom-name" required autoComplete="off" value={name} onChange={(e) => setName(e.target.value)}
              placeholder={kind === "sub" ? "blog" : "example.com"} />
            {kind === "sub" && <p className="text-xs text-slate-500">{fullName} · {t("domains.wildcardHint")}</p>}
          </Field>
          {kind !== "addon" && (
            <Field id="dom-parent" label={kind === "sub" ? t("domains.parentSub") : t("domains.parentAlias")}>
              <select id="dom-parent" className={selectClass} value={parent?.id ?? ""} onChange={(e) => setParentId(e.target.value)}>
                {parents.map((d) => <option key={d.id} value={d.id}>{d.display_name}</option>)}
              </select>
            </Field>
          )}
          {kind !== "alias" && (
            <Field id="dom-docroot" label={t("domains.docroot")}>
              <Input id="dom-docroot" value={docroot} onChange={(e) => setDocroot(e.target.value)}
                placeholder={name ? `domains/${kind === "sub" ? fullName.replace(/^\*\./, "_wildcard.") : name}` : "domains/…"} />
              <p className="text-xs text-slate-500">{t("domains.docrootHint")}</p>
            </Field>
          )}
        </div>
        {needsProof && proof.data ? (
          <Alert kind="info">
            <p className="mb-2">{t("domains.verify.intro", { name: proof.data.name })}</p>
            <dl className="grid gap-1 text-sm sm:grid-cols-[auto_1fr] sm:gap-x-4">
              <dt className="text-slate-500">{t("domains.verify.type")}</dt><dd><code>TXT</code></dd>
              <dt className="text-slate-500">{t("domains.verify.record")}</dt><dd><code className="break-all">{proof.data.record}</code></dd>
              <dt className="text-slate-500">{t("domains.verify.value")}</dt><dd><code className="break-all">{proof.data.value}</code></dd>
            </dl>
            <p className="mt-2">{t("domains.verify.retry")}</p>
          </Alert>
        ) : <ErrorAlert error={add.error} />}
        <Button type="submit" disabled={add.isPending || parents.length === 0}>
          {needsProof ? t("domains.verify.check") : t("domains.add")}
        </Button>
      </form>
    </Card>
  );
}

function Redirects({ domains, redirects, onStarted }: { domains: Domain[]; redirects: Redirect[]; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [domainId, setDomainId] = useState("");
  const [from, setFrom] = useState("/");
  const [target, setTarget] = useState("");
  const [code, setCode] = useState<301 | 302 | 307 | 308>(301);
  const [keepPath, setKeepPath] = useState(false);
  const domain = domains.find((d) => d.id === domainId) ?? domains[0];
  const add = useMutation({
    mutationFn: () => unwrap(api.POST("/domains/{id}/redirects", {
      params: { path: { id: domain!.id } }, body: { path: from, target, code, keep_path: keepPath },
    })),
    onSuccess: (r) => {
      setFrom("/");
      setTarget("");
      onStarted(r);
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/redirects/{id}", { params: { path: { id } } })),
    onSuccess: onStarted,
  });
  return (
    <Card>
      <CardTitle>{t("domains.redirects.title")}</CardTitle>
      <ErrorAlert error={remove.error} />
      {redirects.length === 0 ? <p className="mb-4 text-sm text-slate-500">{t("domains.redirects.empty")}</p> : (
        <ul className="mb-4 divide-y divide-slate-100 text-sm dark:divide-slate-800">
          {redirects.map((r) => (
            <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <span className="break-all">
                <code>{r.domain}{r.path === "/" ? "" : r.path}{r.keep_path ? "/*" : ""}</code>
                {" → "}<code>{r.target}{r.keep_path ? "*" : ""}</code>
                <span className="ml-2 text-xs text-slate-500">{t(`domains.redirects.codes.${r.code}`)}</span>
              </span>
              <Button variant="ghost" disabled={remove.isPending} onClick={() => remove.mutate(r.id)}>{t("common.delete")}</Button>
            </li>
          ))}
        </ul>
      )}
      <form onSubmit={(e) => { e.preventDefault(); add.mutate(); }} className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4">
          <Field id="rd-domain" label={t("domains.redirects.domain")}>
            <select id="rd-domain" className={selectClass} value={domain?.id ?? ""} onChange={(e) => setDomainId(e.target.value)}>
              {domains.map((d) => <option key={d.id} value={d.id}>{d.display_name}</option>)}
            </select>
          </Field>
          <Field id="rd-path" label={t("domains.redirects.path")}>
            <Input id="rd-path" required value={from} onChange={(e) => setFrom(e.target.value)} />
          </Field>
          <Field id="rd-target" label={t("domains.redirects.target")}>
            <Input id="rd-target" required type="url" placeholder="https://example.com/" value={target} onChange={(e) => setTarget(e.target.value)} />
          </Field>
          <Field id="rd-code" label={t("domains.redirects.type")}>
            <select id="rd-code" className={selectClass} value={code} onChange={(e) => setCode(Number(e.target.value) as typeof code)}>
              {([301, 302, 307, 308] as const).map((c) => <option key={c} value={c}>{t(`domains.redirects.codes.${c}`)}</option>)}
            </select>
          </Field>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={keepPath} onChange={(e) => setKeepPath(e.target.checked)} /> {t("domains.redirects.keepPath")}
        </label>
        <ErrorAlert error={add.error} />
        <Button type="submit" disabled={add.isPending || !domain}>{t("domains.redirects.add")}</Button>
      </form>
    </Card>
  );
}
