import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Spinner } from "../components/ui";
import { formatBytes } from "./StatsPage";

/** What was deleted from the home folder: put it back where it was, or delete it for good. */
export function TrashPanel({ accountId, onClose, onChanged }: { accountId: string; onClose: () => void; onChanged: () => void }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const key = ["files-trash", accountId];
  const q = useQuery({ queryKey: key, queryFn: () => unwrap(api.GET("/accounts/{id}/files/trash", { params: { path: { id: accountId } } })), retry: false });
  const [conflicts, setConflicts] = useState<string[]>([]);
  const done = () => { void qc.invalidateQueries({ queryKey: key }); onChanged(); };
  const restore = useMutation({
    mutationFn: (v: { id: string; names?: string[] }) =>
      unwrap(api.POST("/accounts/{id}/files/{op}", { params: { path: { id: accountId, op: "trash-restore" } }, body: v })) as Promise<{ conflicts?: string[] }>,
    onSuccess: (r) => { setConflicts(r.conflicts ?? []); done(); },
  });
  const empty = useMutation({
    mutationFn: (ids?: string[]) => unwrap(api.POST("/accounts/{id}/files/{op}", { params: { path: { id: accountId, op: "trash-empty" } }, body: ids ? { ids } : {} })),
    onSuccess: () => { setConflicts([]); done(); },
  });
  const batches = q.data?.batches ?? [];
  return (
    <Card className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <CardTitle>{t("files.trashTitle")}</CardTitle>
        <div className="flex gap-2">
          <Button variant="danger" disabled={batches.length === 0 || empty.isPending} onClick={() => window.confirm(t("files.confirmEmptyAll")) && empty.mutate(undefined)}>{t("files.emptyAll")}</Button>
          <Button variant="ghost" onClick={onClose}>{t("files.closeTrash")}</Button>
        </div>
      </div>
      <p className="text-sm text-slate-500">{t("files.trashHint")}</p>
      {q.isPending && <Spinner />}
      {q.isError && <ErrorAlert error={q.error} />}
      {(restore.isError || empty.isError) && <ErrorAlert error={restore.error ?? empty.error} />}
      {conflicts.length > 0 && <Alert kind="info">{t("files.restoreConflicts", { names: conflicts.join(", ") })}</Alert>}
      {q.data && batches.length === 0 && <p className="text-sm text-slate-500">{t("files.trashEmpty")}</p>}
      {batches.map((b) => (
        <div key={b.id} className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-sm">
            <span className="text-slate-500">{new Date(b.time).toLocaleString()}</span>
            <span className="flex gap-2">
              <Button variant="secondary" disabled={restore.isPending} onClick={() => restore.mutate({ id: b.id })}>{t("files.restoreAll")}</Button>
              <Button variant="ghost" disabled={empty.isPending} onClick={() => window.confirm(t("files.confirmEmptyOne")) && empty.mutate([b.id])}>{t("files.deleteForGood")}</Button>
            </span>
          </div>
          <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {b.items.map((it) => (
              <li key={it.name} className="flex flex-wrap items-center justify-between gap-2 py-1">
                <span>
                  <span className="font-medium">{it.name}</span>{" "}
                  <span className="text-xs text-slate-500">{it.type === "dir" ? t("files.folder") : formatBytes(it.size)}</span>
                  <span className="block break-all font-mono text-xs text-slate-500">{it.origin ? `→ ~/${it.origin}` : t("files.originUnknown")}</span>
                </span>
                <Button variant="ghost" disabled={restore.isPending} onClick={() => restore.mutate({ id: b.id, names: [it.name] })}>{t("files.restore")}</Button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </Card>
  );
}
