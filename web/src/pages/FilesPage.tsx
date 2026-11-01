import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, getCsrfToken, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { useMe } from "../auth";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Input, Spinner } from "../components/ui";
import { cn } from "../lib/cn";

const CodeEditor = lazy(() => import("../components/CodeEditor"));

type Entry = components["schemas"]["FileEntry"];
type Encoding = NonNullable<components["schemas"]["FileText"]["encoding"]>;

const archiveRe = /\.(zip|tar|tar\.gz|tgz|tar\.zst|tzst|7z)$/i;
const imageRe = /\.(png|jpe?g|gif|webp)$/i;

function formatSize(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

const join = (dir: string, name: string) => (dir ? `${dir}/${name}` : name);
const parent = (p: string) => p.split("/").slice(0, -1).join("/");
const base = (p: string) => p.split("/").pop() ?? p;

/** The file manager (USR-FILE-01..03, 05) for the user's own account. */
export function FilesPage() {
  const { t } = useTranslation();
  const me = useMe();
  if (me.isPending) return <Spinner />;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("files.title")}</h1>
      {me.data?.account_id ? <FileManager accountId={me.data.account_id} /> : <Alert kind="info">{t("domains.noAccount")}</Alert>}
    </div>
  );
}

/** Uploads one file with progress, as the raw request body. */
function uploadFile(accountId: string, path: string, file: Blob, onProgress: (done: number) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const q = new URLSearchParams({ path, overwrite: "true" });
    xhr.open("PUT", `/api/v1/accounts/${encodeURIComponent(accountId)}/files/upload?${q}`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-CSRF-Token", getCsrfToken());
    xhr.upload.onprogress = (e) => onProgress(e.loaded);
    xhr.onload = () => {
      if (xhr.status < 300) return resolve();
      let problem;
      try { problem = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      reject(new ApiError(xhr.status, problem));
    };
    xhr.onerror = () => reject(new Error("upload failed: network error"));
    xhr.send(file);
  });
}

type Dialog =
  | { kind: "mkdir" | "newfile" | "search" }
  | { kind: "rename" | "move" | "copy" | "chmod" | "extract"; entry: Entry }
  | { kind: "compress" };

export function FileManager({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [dir, setDir] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [dialog, setDialog] = useState<Dialog>();
  const [editing, setEditing] = useState<string>();
  const [viewing, setViewing] = useState<string>();
  const [usage, setUsage] = useState(false);
  const [uploads, setUploads] = useState<{ name: string; size: number; done: number; error?: string }[]>([]);
  const [drag, setDrag] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const key = ["files", accountId, dir];
  const list = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/accounts/{id}/files", { params: { path: { id: accountId }, query: { path: dir } } })),
    retry: false,
  });
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["files", accountId] });
    void qc.invalidateQueries({ queryKey: ["files-usage", accountId] });
  };
  const op = useMutation({
    mutationFn: ({ name, body }: { name: "mkdir" | "rename" | "copy" | "trash" | "chmod" | "compress" | "extract"; body: Record<string, unknown> }) =>
      unwrap(api.POST("/accounts/{id}/files/{op}", { params: { path: { id: accountId, op: name } }, body })),
    onSuccess: () => { setDialog(undefined); setSelected([]); refresh(); },
  });
  const go = (p: string) => { setDir(p); setSelected([]); setDialog(undefined); };

  const upload = async (files: { file: File; rel: string }[]) => {
    setUploads(files.map((f) => ({ name: f.rel, size: f.file.size, done: 0 })));
    for (const [i, f] of files.entries()) {
      try {
        await uploadFile(accountId, join(dir, f.rel), f.file, (done) => setUploads((u) => u.map((x, j) => (j === i ? { ...x, done } : x))));
        setUploads((u) => u.map((x, j) => (j === i ? { ...x, done: x.size } : x)));
      } catch (e) {
        setUploads((u) => u.map((x, j) => (j === i ? { ...x, error: e instanceof Error ? e.message : String(e) } : x)));
      }
    }
    refresh();
  };
  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDrag(false);
    void upload(Array.from(e.dataTransfer.files, (file) => ({ file, rel: file.name })));
  };

  const crumbs = dir ? dir.split("/") : [];
  const items = list.data?.items ?? [];
  const toggle = (p: string) => setSelected(selected.includes(p) ? selected.filter((x) => x !== p) : [...selected, p]);
  const download = (p: string, inline = false) =>
    `/api/v1/accounts/${encodeURIComponent(accountId)}/files/download?${new URLSearchParams({ path: p, ...(inline ? { inline: "1" } : {}) })}`;

  return (
    <div className="space-y-4">
      <Card className="space-y-3">
        <nav aria-label={t("files.location")} className="flex flex-wrap items-center gap-1 text-sm">
          <button type="button" className="font-medium text-brand hover:underline" onClick={() => go("")}>{t("files.home")}</button>
          {crumbs.map((c, i) => (
            <span key={i} className="flex items-center gap-1">
              <span className="text-slate-400">/</span>
              <button type="button" className="text-brand hover:underline" onClick={() => go(crumbs.slice(0, i + 1).join("/"))}>{c}</button>
            </span>
          ))}
        </nav>
        <div className="flex flex-wrap gap-2">
          {dir && <Button variant="ghost" onClick={() => go(parent(dir))}>{t("files.up")}</Button>}
          <Button variant="secondary" onClick={() => setDialog({ kind: "mkdir" })}>{t("files.newFolder")}</Button>
          <Button variant="secondary" onClick={() => setDialog({ kind: "newfile" })}>{t("files.newFile")}</Button>
          <Button variant="secondary" onClick={() => fileInput.current?.click()}>{t("files.upload")}</Button>
          <input ref={fileInput} type="file" multiple hidden onChange={(e) => {
            const fl = Array.from(e.target.files ?? []);
            e.target.value = "";
            void upload(fl.map((file) => ({ file, rel: file.name })));
          }} />
          <Button variant="ghost" onClick={() => setDialog({ kind: "search" })}>{t("files.search")}</Button>
          <Button variant="ghost" onClick={() => setUsage(!usage)}>{usage ? t("files.hideUsage") : t("files.usage")}</Button>
          {selected.length > 0 && <>
            <Button variant="ghost" onClick={() => setDialog({ kind: "compress" })}>{t("files.compress", { count: selected.length })}</Button>
            <Button variant="danger" disabled={op.isPending}
              onClick={() => window.confirm(t("files.confirmTrash", { count: selected.length })) && op.mutate({ name: "trash", body: { paths: selected } })}>
              {t("files.trash", { count: selected.length })}
            </Button>
          </>}
        </div>
        {dialog && <DialogForm d={dialog} dir={dir} accountId={accountId} op={op} onClose={() => setDialog(undefined)}
          onEdit={(p) => { setDialog(undefined); setEditing(p); }} onGo={go} selected={selected} />}
        <ErrorAlert error={op.error} />
        {uploads.length > 0 && (
          <div className="space-y-1 text-xs">
            {uploads.map((u, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="w-64 truncate">{u.name}</span>
                {u.error ? <span className="text-red-700 dark:text-red-400">{u.error}</span>
                  : <progress className="w-48" max={u.size || 1} value={u.done} aria-label={u.name} />}
              </div>
            ))}
            {uploads.every((u) => u.error || u.done >= u.size) && <button type="button" className="text-brand hover:underline" onClick={() => setUploads([])}>{t("files.clearUploads")}</button>}
          </div>
        )}
      </Card>

      {usage && <UsagePanel accountId={accountId} dir={dir} onGo={go} />}

      <Card className={cn("overflow-x-auto p-0", drag && "ring-2 ring-brand")}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={onDrop}>
        {list.isPending ? <div className="p-6"><Spinner /></div> : list.error ? <div className="p-4"><ErrorAlert error={list.error} /></div> : (
          <table className="w-full text-left text-sm">
            <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
              <tr>
                <th className="w-8 px-4 py-3"><span className="sr-only">{t("files.select")}</span></th>
                {["files.name", "files.size", "files.permissions", "files.owner", "files.modified", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(k)}</th>)}
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.path} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="px-4 py-2"><input type="checkbox" aria-label={e.name} checked={selected.includes(e.path)} onChange={() => toggle(e.path)} /></td>
                  <td className="px-4 py-2">
                    {e.type === "dir" ? <button type="button" className="font-medium text-brand hover:underline" onClick={() => go(e.path)}>📁 {e.name}</button>
                      : e.type === "file" ? <button type="button" className="hover:underline"
                        onClick={() => (imageRe.test(e.name) ? setViewing(e.path) : setEditing(e.path))}>{e.name}</button>
                      : <span className="text-slate-500">{e.name} {e.type === "link" && `(${t("files.link")})`}</span>}
                  </td>
                  <td className="px-4 py-2 text-slate-600 dark:text-slate-400">{e.type === "file" ? formatSize(e.size) : ""}</td>
                  <td className="px-4 py-2 font-mono text-xs">{e.mode}</td>
                  <td className="px-4 py-2 text-xs text-slate-500">{e.owner}{e.group && e.group !== e.owner ? `:${e.group}` : ""}</td>
                  <td className="whitespace-nowrap px-4 py-2 text-xs text-slate-500">{new Date(e.mod_time).toLocaleString()}</td>
                  <td className="whitespace-nowrap px-4 py-2 text-right text-xs">
                    {e.type === "file" && <a className="mr-2 text-brand hover:underline" href={download(e.path)}>{t("files.download")}</a>}
                    {e.type === "file" && archiveRe.test(e.name) && <button type="button" className="mr-2 text-brand hover:underline" onClick={() => setDialog({ kind: "extract", entry: e })}>{t("files.extract")}</button>}
                    {(["rename", "move", "copy", "chmod"] as const).map((k) => (
                      e.type !== "link" || k === "rename" || k === "move"
                        ? <button key={k} type="button" className="mr-2 text-brand hover:underline" onClick={() => setDialog({ kind: k, entry: e })}>{t(`files.${k}`)}</button>
                        : null
                    ))}
                  </td>
                </tr>
              ))}
              {items.length === 0 && <tr><td colSpan={7} className="px-4 py-6 text-center text-slate-500">{t("files.empty")}</td></tr>}
            </tbody>
          </table>
        )}
        <p className="border-t border-slate-100 px-4 py-2 text-xs text-slate-500 dark:border-slate-800">{t("files.dropHint")}</p>
      </Card>

      {editing && <Editor accountId={accountId} path={editing} onClose={() => { setEditing(undefined); refresh(); }} />}
      {viewing && (
        <Card className="space-y-3">
          <div className="flex items-center justify-between"><CardTitle>{base(viewing)}</CardTitle><Button variant="ghost" onClick={() => setViewing(undefined)}>{t("common.cancel")}</Button></div>
          <img src={download(viewing, true)} alt={base(viewing)} className="max-h-[70vh] max-w-full" />
        </Card>
      )}
    </div>
  );
}

type OpMutation = { mutate: (v: { name: "mkdir" | "rename" | "copy" | "trash" | "chmod" | "compress" | "extract"; body: Record<string, unknown> }) => void; isPending: boolean };

/** The small forms for naming, moving, permissions and archives. */
function DialogForm({ d, dir, accountId, op, onClose, onEdit, onGo, selected }: {
  d: Dialog; dir: string; accountId: string; op: OpMutation; onClose: () => void; onEdit: (p: string) => void; onGo: (p: string) => void; selected: string[];
}) {
  const { t } = useTranslation();
  const entry = "entry" in d ? d.entry : undefined;
  const initial = {
    mkdir: "", newfile: "", search: "", compress: `${base(selected[0] ?? "archive")}.zip`,
    rename: entry?.name ?? "", move: entry ? parent(entry.path) : "", copy: entry ? join(parent(entry.path), `${entry.name}-copy`) : "",
    chmod: entry?.mode.slice(1) ?? "644", extract: entry ? join(parent(entry.path), entry.name.replace(archiveRe, "")) : "",
  }[d.kind];
  const [value, setValue] = useState(initial);
  const [recursive, setRecursive] = useState(false);
  const [format, setFormat] = useState<"zip" | "tar.gz">("zip");
  const submit = () => {
    switch (d.kind) {
      case "mkdir": return op.mutate({ name: "mkdir", body: { path: join(dir, value) } });
      case "newfile": return onEdit(join(dir, value));
      case "search": return undefined; // its own form below
      case "rename": return op.mutate({ name: "rename", body: { from: d.entry.path, to: join(parent(d.entry.path), value) } });
      case "move": return op.mutate({ name: "rename", body: { from: d.entry.path, to: join(value.replace(/^\/+|\/+$/g, ""), d.entry.name) } });
      case "copy": return op.mutate({ name: "copy", body: { from: d.entry.path, to: value } });
      case "chmod": return op.mutate({ name: "chmod", body: { path: d.entry.path, mode: value, recursive } });
      case "extract": return op.mutate({ name: "extract", body: { path: d.entry.path, to: value } });
      case "compress": return op.mutate({ name: "compress", body: { paths: selected, to: join(dir, value), format } });
    }
  };
  if (d.kind === "search") return <SearchForm accountId={accountId} dir={dir} onGo={onGo} onClose={onClose} />;
  return (
    <form onSubmit={(e) => { e.preventDefault(); submit(); }} className="flex flex-wrap items-center gap-2 rounded-md bg-slate-50 p-3 text-sm dark:bg-slate-900">
      <label htmlFor="file-dialog" className="font-medium">{t(`files.dialogs.${d.kind}`, { name: entry?.name ?? "" })}</label>
      <Input id="file-dialog" className="max-w-md" autoFocus value={value} onChange={(e) => setValue(e.target.value)} required={d.kind !== "move"} />
      {d.kind === "chmod" && entry?.type === "dir" && (
        <label className="flex items-center gap-1"><input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} /> {t("files.recursive")}</label>
      )}
      {d.kind === "compress" && (
        <select aria-label={t("files.format")} className="rounded-md border border-slate-300 bg-white px-2 py-1 dark:border-slate-700 dark:bg-slate-900" value={format}
          onChange={(e) => { const f = e.target.value as "zip" | "tar.gz"; setFormat(f); setValue(value.replace(/\.(zip|tar\.gz)$/, "") + "." + f); }}>
          <option value="zip">zip</option><option value="tar.gz">tar.gz</option>
        </select>
      )}
      <Button type="submit" variant="secondary" disabled={op.isPending}>{t("common.save")}</Button>
      <Button type="button" variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
    </form>
  );
}

function SearchForm({ accountId, dir, onGo, onClose }: { accountId: string; dir: string; onGo: (p: string) => void; onClose: () => void }) {
  const { t } = useTranslation();
  const [q, setQ] = useState("");
  const search = useMutation({
    mutationFn: () => unwrap(api.GET("/accounts/{id}/files/search", { params: { path: { id: accountId }, query: { path: dir, q } } })),
  });
  return (
    <div className="space-y-2 rounded-md bg-slate-50 p-3 text-sm dark:bg-slate-900">
      <form onSubmit={(e) => { e.preventDefault(); search.mutate(); }} className="flex flex-wrap items-center gap-2">
        <Input aria-label={t("files.search")} autoFocus placeholder={t("files.searchHint")} className="max-w-md" value={q} onChange={(e) => setQ(e.target.value)} required />
        <Button type="submit" variant="secondary" disabled={search.isPending}>{t("files.search")}</Button>
        <Button type="button" variant="ghost" onClick={onClose}>{t("common.cancel")}</Button>
      </form>
      <ErrorAlert error={search.error} />
      {search.data && (
        <ul className="space-y-1">
          {search.data.items.map((e) => (
            <li key={e.path}><button type="button" className="text-brand hover:underline" onClick={() => onGo(e.type === "dir" ? e.path : parent(e.path))}>{e.path}</button></li>
          ))}
          {search.data.items.length === 0 && <li className="text-slate-500">{t("files.noResults")}</li>}
          {search.data.more && <li className="text-slate-500">{t("files.moreResults")}</li>}
        </ul>
      )}
    </div>
  );
}

function UsagePanel({ accountId, dir, onGo }: { accountId: string; dir: string; onGo: (p: string) => void }) {
  const { t } = useTranslation();
  const u = useQuery({
    queryKey: ["files-usage", accountId, dir],
    queryFn: () => unwrap(api.GET("/accounts/{id}/files/usage", { params: { path: { id: accountId }, query: { path: dir } } })),
    retry: false,
  });
  if (u.isPending) return <Spinner />;
  if (!u.data) return <ErrorAlert error={u.error} />;
  const max = Math.max(1, ...u.data.children.map((c) => c.size));
  return (
    <Card className="grid gap-6 md:grid-cols-2">
      <div>
        <CardTitle>{t("files.usageTitle", { size: formatSize(u.data.total) })}</CardTitle>
        <ul className="space-y-1 text-sm">
          {u.data.children.filter((c) => c.size > 0).map((c) => (
            <li key={c.path} className="flex items-center gap-2">
              <button type="button" className="w-40 truncate text-left text-brand hover:underline" disabled={c.type !== "dir"} onClick={() => onGo(c.path)}>{c.name}</button>
              <meter className="h-2 w-40" min={0} max={max} value={c.size} aria-label={c.name} />
              <span className="text-xs text-slate-500">{formatSize(c.size)}</span>
            </li>
          ))}
        </ul>
        {u.data.partial && <p className="mt-2 text-xs text-slate-500">{t("files.partial")}</p>}
      </div>
      <div>
        <CardTitle>{t("files.largest")}</CardTitle>
        <ul className="space-y-1 text-sm">
          {u.data.largest.map((f) => (
            <li key={f.path} className="flex justify-between gap-2"><span className="truncate">{f.path}</span><span className="text-xs text-slate-500">{formatSize(f.size)}</span></li>
          ))}
        </ul>
      </div>
    </Card>
  );
}

/** Opens a text file in the code editor; a new path makes a new file. */
function Editor({ accountId, path, onClose }: { accountId: string; path: string; onClose: () => void }) {
  const { t } = useTranslation();
  const [encoding, setEncoding] = useState("");
  const [text, setText] = useState<string>();
  const load = useQuery({
    queryKey: ["file-text", accountId, path, encoding],
    queryFn: async () => {
      try {
        const r = await unwrap(api.GET("/accounts/{id}/files/text", { params: { path: { id: accountId }, query: { path, encoding: (encoding || undefined) as Encoding | undefined } } }));
        setText(r.content);
        setEncoding(r.encoding ?? "utf-8");
        return r;
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) { setText(""); setEncoding("utf-8"); return { content: "", encoding: "utf-8" }; }
        throw e;
      }
    },
    retry: false, refetchOnWindowFocus: false,
  });
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/accounts/{id}/files/text", {
      params: { path: { id: accountId }, query: { path } }, body: { content: text ?? "", encoding: (encoding || "utf-8") as Encoding },
    })),
  });
  const dark = typeof window !== "undefined" && document.documentElement.classList.contains("dark");
  return (
    <Card className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <CardTitle>{path}</CardTitle>
        <div className="flex items-center gap-2 text-sm">
          <select aria-label={t("files.encoding")} className="rounded-md border border-slate-300 bg-white px-2 py-1 dark:border-slate-700 dark:bg-slate-900"
            value={encoding} onChange={(e) => setEncoding(e.target.value)}>
            {["utf-8", "iso-8859-1", "iso-8859-15", "windows-1252"].map((e) => <option key={e} value={e}>{e}</option>)}
          </select>
          <Button disabled={save.isPending || text === undefined} onClick={() => save.mutate()}>{t("common.save")}</Button>
          <Button variant="ghost" onClick={onClose}>{t("files.close")}</Button>
        </div>
      </div>
      <ErrorAlert error={load.error ?? save.error} />
      {save.isSuccess && <Alert kind="success">{t("common.saved")}</Alert>}
      {text === undefined ? <Spinner /> : (
        <Suspense fallback={<Spinner />}>
          <CodeEditor name={path} value={text} onChange={setText} dark={dark} />
        </Suspense>
      )}
    </Card>
  );
}
