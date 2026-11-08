import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { JobNotice } from "../components/JobNotice";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { formatBytes } from "./StatsPage";

type Destination = components["schemas"]["BackupDestination"];
type Input_ = components["schemas"]["BackupDestinationInput"];
type Copy = components["schemas"]["RemoteCopy"];

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";
const areaClass = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-xs dark:border-slate-700 dark:bg-slate-900";

function useDestinations(enabled = true) {
  return useQuery({ queryKey: ["backup-destinations"], queryFn: () => unwrap(api.GET("/server/backup-destinations")), retry: false, enabled });
}

/** A choice of destination, or none. */
export function DestinationSelect({ id, value, onChange, none }: { id: string; value: string; onChange: (v: string) => void; none: string }) {
  const q = useDestinations();
  return (
    <select id={id} className={selectClass} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{none}</option>
      {q.data?.items.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
    </select>
  );
}

/** Where a backup is copied to, and a way to copy it (admins). */
export function RemoteBadges({ copies, backupId, onChanged }: { copies?: Copy[]; backupId?: string; onChanged: () => void }) {
  const { t } = useTranslation();
  const [dest, setDest] = useState("");
  const [jobId, setJobId] = useState<string>();
  const list = useDestinations(copies !== undefined);
  const send = useMutation({
    mutationFn: () => unwrap(api.POST("/backups/{id}/upload", { params: { path: { id: backupId! } }, body: { destination_id: dest } })),
    onSuccess: (r) => setJobId(r.job_id),
  });
  if (copies === undefined) return null; // not an admin: users do not see where copies are
  return (
    <div className="mt-1 space-y-1 text-xs">
      {copies.map((c) => (
        <div key={c.destination_id} className={c.status === "failed" ? "text-red-700 dark:text-red-400" : c.status === "ok" ? "text-green-700 dark:text-green-400" : "text-slate-500"}>
          {c.destination}: {c.status}{c.status === "ok" ? ` (${formatBytes(c.size)})` : ""}{c.detail ? `: ${c.detail}` : ""}
        </div>
      ))}
      {backupId && list.data && list.data.items.length > 0 && (
        <div className="flex items-center gap-2">
          <select aria-label={t("backups.destinations.send")} className={selectClass} value={dest} onChange={(e) => setDest(e.target.value)}>
            <option value="">{t("backups.destinations.send")}</option>
            {list.data.items.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
          <Button variant="ghost" disabled={!dest || send.isPending} onClick={() => send.mutate()}>{t("backups.destinations.sendNow")}</Button>
        </div>
      )}
      {send.isError && <ErrorAlert error={send.error} />}
      {jobId && <JobNotice jobId={jobId} onDone={onChanged} />}
    </div>
  );
}

/** The destinations for admins: add, test, look into, forget. */
export function DestinationsCard() {
  const { t } = useTranslation();
  const q = useDestinations();
  return (
    <Card>
      <CardTitle>{t("backups.destinations.title")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("backups.destinations.hint")}</p>
      {q.isPending && <Spinner />}
      {q.isError && <ErrorAlert error={q.error} />}
      <div className="space-y-3">
        {q.data?.items.map((d) => <DestinationRow key={d.id} d={d} />)}
        {q.data?.items.length === 0 && <p className="text-sm text-slate-500">{t("backups.destinations.none")}</p>}
      </div>
      <AddDestination />
    </Card>
  );
}

function summary(d: Destination): string {
  switch (d.kind) {
    case "folder": return d.path;
    case "sftp": return `${d.user}@${d.host}:${d.port}/${d.path}`;
    default: return `${d.endpoint || "s3.amazonaws.com"}/${d.bucket}${d.path ? "/" + d.path : ""}`;
  }
}

function DestinationRow({ d }: { d: Destination }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["backup-destinations"] });
  const test = useMutation({ mutationFn: () => unwrap(api.POST("/server/backup-destinations/{id}/test", { params: { path: { id: d.id } } })) });
  const del = useMutation({ mutationFn: () => unwrap(api.DELETE("/server/backup-destinations/{id}", { params: { path: { id: d.id } } })), onSuccess: refresh });
  return (
    <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <span className="font-medium">{d.name}</span> <span className="text-xs text-slate-500">{t(`backups.destinations.${d.kind}`)}</span>
          <div className="break-all font-mono text-xs text-slate-500">{summary(d)}</div>
          {d.kind === "sftp" && <div className="break-all font-mono text-xs text-slate-500">{d.host_key}</div>}
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" disabled={test.isPending} onClick={() => test.mutate()}>{t("backups.destinations.test")}</Button>
          <Button variant="ghost" onClick={() => setOpen(!open)}>{t(open ? "backups.destinations.hideFiles" : "backups.destinations.files")}</Button>
          <Button variant="ghost" disabled={del.isPending} onClick={() => window.confirm(t("backups.destinations.confirmDelete", { name: d.name })) && del.mutate()}>{t("backups.destinations.delete")}</Button>
        </div>
      </div>
      {test.isSuccess && <Alert kind="success">{t("backups.destinations.works")}</Alert>}
      {(test.isError || del.isError) && <ErrorAlert error={test.error ?? del.error} />}
      {open && <Files id={d.id} />}
    </div>
  );
}

function Files({ id }: { id: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string>();
  const q = useQuery({ queryKey: ["backup-destination-files", id], queryFn: () => unwrap(api.GET("/server/backup-destinations/{id}/files", { params: { path: { id } } })), retry: false });
  const fetchIt = useMutation({
    mutationFn: (f: { username: string; file: string }) => unwrap(api.POST("/server/backup-destinations/{id}/fetch", { params: { path: { id } }, body: f })),
    onSuccess: (r) => setJobId(r.job_id),
  });
  if (q.isPending) return <Spinner />;
  if (!q.data) return <ErrorAlert error={q.error} />;
  return (
    <div className="mt-3 overflow-x-auto">
      {jobId && <JobNotice jobId={jobId} onDone={() => { void qc.invalidateQueries({ queryKey: ["backup-destination-files", id] }); void qc.invalidateQueries({ queryKey: ["orphan-backups"] }); }} />}
      {fetchIt.isError && <ErrorAlert error={fetchIt.error} />}
      <table className="w-full text-left text-sm">
        <thead className="text-slate-500"><tr>{["account", "file", "size"].map((k) => <th key={k} className="py-1 pr-4 font-medium">{t(`backups.destinations.${k}`)}</th>)}<th /></tr></thead>
        <tbody>
          {q.data.items.map((f) => (
            <tr key={f.username + f.file} className="border-t border-slate-100 dark:border-slate-800">
              <td className="py-1 pr-4">{f.username}</td>
              <td className="py-1 pr-4 font-mono text-xs">{f.file}</td>
              <td className="py-1 pr-4">{formatBytes(f.size)}</td>
              <td className="py-1 text-right">
                {f.on_server ? <span className="text-xs text-slate-500">{t("backups.destinations.onServer")}</span>
                  : <Button variant="ghost" disabled={fetchIt.isPending} onClick={() => fetchIt.mutate({ username: f.username, file: f.file })}>{t("backups.destinations.fetch")}</Button>}
              </td>
            </tr>
          ))}
          {q.data.items.length === 0 && <tr><td colSpan={4} className="py-3 text-slate-500">{t("backups.destinations.noFiles")}</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

const empty: Input_ = {
  name: "", kind: "folder", path: "", host: "", port: 22, user: "", password: "", private_key: "", host_key: "",
  endpoint: "", region: "", bucket: "", access_key: "", secret_key: "", use_tls: true,
};

function AddDestination() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [f, setF] = useState<Input_>(empty);
  const create = useMutation({
    mutationFn: () => unwrap(api.POST("/server/backup-destinations", { body: f })),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["backup-destinations"] }); },
  });
  const set = (k: keyof Input_) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  return (
    <form onSubmit={(e) => { e.preventDefault(); create.mutate(); }} className="mt-5 space-y-3 border-t border-slate-200 pt-4 dark:border-slate-800">
      <div className="grid gap-3 md:grid-cols-2">
        <Field id="dst-name" label={t("backups.destinations.name")}><Input id="dst-name" required value={f.name} onChange={set("name")} /></Field>
        <Field id="dst-kind" label={t("backups.destinations.kind")}>
          <select id="dst-kind" className={selectClass} value={f.kind} onChange={(e) => setF({ ...empty, name: f.name, kind: e.target.value as Input_["kind"] })}>
            {(["folder", "sftp", "s3"] as const).map((k) => <option key={k} value={k}>{t(`backups.destinations.${k}`)}</option>)}
          </select>
        </Field>
      </div>
      {f.kind === "folder" && (
        <Field id="dst-path" label={t("backups.destinations.path")}>
          <Input id="dst-path" required placeholder="/mnt/backup" value={f.path ?? ""} onChange={set("path")} />
          <p className="text-xs text-slate-500">{t("backups.destinations.folderHint")}</p>
        </Field>
      )}
      {f.kind === "sftp" && (
        <div className="grid gap-3 md:grid-cols-2">
          <Field id="dst-host" label={t("backups.destinations.host")}><Input id="dst-host" required value={f.host ?? ""} onChange={set("host")} /></Field>
          <Field id="dst-port" label={t("backups.destinations.port")}><Input id="dst-port" type="number" min={1} max={65535} value={f.port ?? 22} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} /></Field>
          <Field id="dst-user" label={t("backups.destinations.user")}><Input id="dst-user" required value={f.user ?? ""} onChange={set("user")} /></Field>
          <Field id="dst-spath" label={t("backups.destinations.sftpPath")}><Input id="dst-spath" placeholder="backups/xcp" value={f.path ?? ""} onChange={set("path")} /></Field>
          <Field id="dst-pw" label={t("backups.destinations.password")}><Input id="dst-pw" type="password" autoComplete="off" value={f.password ?? ""} onChange={set("password")} /></Field>
          <Field id="dst-hk" label={t("backups.destinations.hostKey")}>
            <Input id="dst-hk" placeholder="SHA256:..." value={f.host_key ?? ""} onChange={set("host_key")} />
            <p className="text-xs text-slate-500">{t("backups.destinations.hostKeyHint")}</p>
          </Field>
          <div className="md:col-span-2">
            <Field id="dst-key" label={t("backups.destinations.privateKey")}>
              <textarea id="dst-key" rows={4} className={areaClass} autoComplete="off" value={f.private_key ?? ""} onChange={set("private_key")} />
            </Field>
          </div>
        </div>
      )}
      {f.kind === "s3" && (
        <div className="grid gap-3 md:grid-cols-2">
          <Field id="dst-ep" label={t("backups.destinations.endpoint")}><Input id="dst-ep" placeholder="minio.example.com:9000" value={f.endpoint ?? ""} onChange={set("endpoint")} /></Field>
          <Field id="dst-region" label={t("backups.destinations.region")}><Input id="dst-region" placeholder="eu-west-1" value={f.region ?? ""} onChange={set("region")} /></Field>
          <Field id="dst-bucket" label={t("backups.destinations.bucket")}><Input id="dst-bucket" required value={f.bucket ?? ""} onChange={set("bucket")} /></Field>
          <Field id="dst-prefix" label={t("backups.destinations.prefix")}><Input id="dst-prefix" placeholder="xcp" value={f.path ?? ""} onChange={set("path")} /></Field>
          <Field id="dst-ak" label={t("backups.destinations.accessKey")}><Input id="dst-ak" required autoComplete="off" value={f.access_key ?? ""} onChange={set("access_key")} /></Field>
          <Field id="dst-sk" label={t("backups.destinations.secretKey")}><Input id="dst-sk" type="password" required autoComplete="off" value={f.secret_key ?? ""} onChange={set("secret_key")} /></Field>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.use_tls ?? true} onChange={(e) => setF({ ...f, use_tls: e.target.checked })} />{t("backups.destinations.tls")}</label>
        </div>
      )}
      {create.isError && <ErrorAlert error={create.error} />}
      {create.data?.host_key_new && <Alert kind="info">{t("backups.destinations.hostKeyNew", { key: create.data.host_key })}</Alert>}
      <Button type="submit" disabled={create.isPending}>{t("backups.destinations.add")}</Button>
    </form>
  );
}
