import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { ErrorAlert } from "../components/ErrorAlert";

type Limits = components["schemas"]["Limits"];
type NumericLimit = Exclude<keyof Limits, "shell" | "php_versions" | "dedicated_ip">;

const groups: Record<string, NumericLimit[]> = {
  storage: ["disk_mb", "inodes", "bandwidth_mb"],
  domains: ["addon_domains", "subdomains", "aliases"],
  email: ["mailboxes", "mailbox_mb", "forwarders", "mail_per_hour"],
  databases: ["databases", "db_users", "ftp_accounts", "cron_jobs"],
  resources: ["cpu_percent", "memory_mb", "processes", "io_mbps"],
};

export function usePackages() {
  return useQuery({ queryKey: ["packages"], queryFn: () => unwrap(api.GET("/packages")) });
}

export function useFeatureLists() {
  return useQuery({ queryKey: ["feature-lists"], queryFn: () => unwrap(api.GET("/feature-lists")) });
}

/** Formats a limit in MB as MB/GB/TB; null is unlimited. */
function size(mb: number | null | undefined, unlimited: string) {
  if (mb == null) return unlimited;
  if (mb >= 1024 * 1024) return `${+(mb / 1024 / 1024).toFixed(1)} TB`;
  if (mb >= 1024) return `${+(mb / 1024).toFixed(1)} GB`;
  return `${mb} MB`;
}

export function PackagesPage() {
  const { t } = useTranslation();
  const packages = usePackages();
  const lists = useFeatureLists();
  const unl = t("common.unlimited");
  const count = (n: number | null | undefined) => (n == null ? unl : String(n));
  const listName = (id: string) => lists.data?.items.find((l) => l.id === id)?.name ?? "";

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t("packages.title")}</h1>
        <Link to="/packages/$packageId" params={{ packageId: "new" }}>
          <Button>{t("packages.new")}</Button>
        </Link>
      </div>
      <ErrorAlert error={packages.error} />
      {packages.isPending ? (
        <Spinner />
      ) : (
        <Card className="overflow-x-auto p-0">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
              <tr>
                {["packages.name", "packages.columns.disk", "packages.columns.traffic", "packages.columns.domains",
                  "packages.columns.mailboxes", "packages.columns.databases", "packages.featureList"].map((k) => (
                  <th key={k} className="px-4 py-3 font-medium">{t(k)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {packages.data?.items.map((p) => (
                <tr key={p.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="px-4 py-3">
                    <Link to="/packages/$packageId" params={{ packageId: p.id }} className="font-medium text-brand hover:underline">
                      {p.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3">{size(p.limits.disk_mb, unl)}</td>
                  <td className="px-4 py-3">{size(p.limits.bandwidth_mb, unl)}</td>
                  <td className="px-4 py-3">{count(p.limits.addon_domains)}</td>
                  <td className="px-4 py-3">{count(p.limits.mailboxes)}</td>
                  <td className="px-4 py-3">{count(p.limits.databases)}</td>
                  <td className="px-4 py-3">{listName(p.feature_list_id)}</td>
                </tr>
              ))}
              {packages.data?.items.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-6 text-center text-slate-500">{t("packages.empty")}</td></tr>
              )}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

export function PackageEditPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { packageId = "new" } = useParams({ strict: false }) as { packageId?: string };
  const isNew = packageId === "new";
  const lists = useFeatureLists();
  const existing = useQuery({
    queryKey: ["packages", packageId],
    queryFn: () => unwrap(api.GET("/packages/{id}", { params: { path: { id: packageId } } })),
    enabled: !isNew,
  });

  const [name, setName] = useState("");
  const [featureListId, setFeatureListId] = useState("");
  const [nums, setNums] = useState<Partial<Record<NumericLimit, string>>>({});
  const [shell, setShell] = useState<"none" | "jailed" | "full">("none");
  const [php, setPhp] = useState("");
  const [dedicatedIp, setDedicatedIp] = useState(false);

  useEffect(() => {
    const p = existing.data;
    if (!p) return;
    setName(p.name);
    setFeatureListId(p.feature_list_id);
    const n: Partial<Record<NumericLimit, string>> = {};
    for (const keys of Object.values(groups)) for (const k of keys) n[k] = p.limits[k] == null ? "" : String(p.limits[k]);
    setNums(n);
    setShell(p.limits.shell ?? "none");
    setPhp((p.limits.php_versions ?? []).join(", "));
    setDedicatedIp(!!p.limits.dedicated_ip);
  }, [existing.data]);

  useEffect(() => {
    if (isNew && !featureListId && lists.data?.items[0]) setFeatureListId(lists.data.items[0].id);
  }, [isNew, featureListId, lists.data]);

  const body = () => {
    const limits: Limits = { shell, dedicated_ip: dedicatedIp, php_versions: php.split(/[\s,]+/).filter(Boolean) };
    for (const keys of Object.values(groups)) {
      for (const k of keys) {
        const v = nums[k]?.trim();
        limits[k] = v ? Number(v) : null;
      }
    }
    return { name, feature_list_id: featureListId, limits };
  };

  const save = useMutation({
    mutationFn: () =>
      isNew
        ? unwrap(api.POST("/packages", { body: body() }))
        : unwrap(api.PUT("/packages/{id}", { params: { path: { id: packageId } }, body: body() })),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["packages"] });
      await navigate({ to: "/packages" });
    },
  });
  const remove = useMutation({
    mutationFn: () => unwrap(api.DELETE("/packages/{id}", { params: { path: { id: packageId } } })),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["packages"] });
      await navigate({ to: "/packages" });
    },
  });

  if (!isNew && existing.isPending) return <Spinner />;

  function submit(e: FormEvent) {
    e.preventDefault();
    save.mutate();
  }

  return (
    <form onSubmit={submit} className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t(isNew ? "packages.new" : "packages.edit")}</h1>
        <Link to="/packages"><Button type="button" variant="secondary">{t("common.back")}</Button></Link>
      </div>
      <ErrorAlert error={existing.error ?? save.error ?? remove.error} />
      <Card className="grid gap-4 md:grid-cols-2">
        <Field id="name" label={t("packages.name")}>
          <Input id="name" required maxLength={64} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field id="fl" label={t("packages.featureList")}>
          <select id="fl" required value={featureListId} onChange={(e) => setFeatureListId(e.target.value)}
            className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
            {lists.data?.items.map((l) => <option key={l.id} value={l.id}>{l.name}</option>)}
          </select>
        </Field>
      </Card>
      <p className="text-sm text-slate-500">{t("packages.unlimitedHint")}</p>
      {Object.entries(groups).map(([group, keys]) => (
        <Card key={group}>
          <CardTitle>{t(`packages.groups.${group}`)}</CardTitle>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {keys.map((k) => (
              <Field key={k} id={k} label={t(`packages.limits.${k}`)}>
                <Input id={k} type="number" min={0} inputMode="numeric" placeholder={t("common.unlimited")}
                  value={nums[k] ?? ""} onChange={(e) => setNums({ ...nums, [k]: e.target.value })} />
              </Field>
            ))}
          </div>
        </Card>
      ))}
      <Card>
        <CardTitle>{t("packages.groups.access")}</CardTitle>
        <div className="grid gap-4 md:grid-cols-2">
          <Field id="shell" label={t("packages.limits.shell")}>
            <select id="shell" value={shell} onChange={(e) => setShell(e.target.value as typeof shell)}
              className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900">
              {(["none", "jailed", "full"] as const).map((s) => <option key={s} value={s}>{t(`packages.shell.${s}`)}</option>)}
            </select>
          </Field>
          <Field id="php" label={t("packages.limits.php_versions")}>
            <Input id="php" placeholder="8.2, 8.3" value={php} onChange={(e) => setPhp(e.target.value)} />
            <p className="text-xs text-slate-500">{t("packages.limits.php_versions_hint")}</p>
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={dedicatedIp} onChange={(e) => setDedicatedIp(e.target.checked)} />
            {t("packages.limits.dedicated_ip")}
          </label>
        </div>
      </Card>
      <div className="flex gap-2">
        <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
        {!isNew && (
          <Button type="button" variant="danger" disabled={remove.isPending}
            onClick={() => window.confirm(t("common.confirmDelete", { name })) && remove.mutate()}>
            {t("common.delete")}
          </Button>
        )}
      </div>
      {save.isSuccess && <Alert kind="success">{t("common.saved")}</Alert>}
    </form>
  );
}
