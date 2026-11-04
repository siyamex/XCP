import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import { ErrorAlert } from "../components/ErrorAlert";
import { Button, Card, CardTitle, Spinner } from "../components/ui";

type Action = "flush_all" | "flush" | "delete" | "delete_all";

/** Postfix's queue for admins: look at what waits and why, flush or delete it. */
export function MailQueueCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["mail-queue"], queryFn: () => unwrap(api.GET("/server/mail/queue")), retry: false, refetchInterval: 30000 });
  const [picked, setPicked] = useState<string[]>([]);
  const act = useMutation({
    mutationFn: (v: { action: Action; ids?: string[] }) => unwrap(api.POST("/server/mail/queue", { body: v })),
    onSuccess: () => { setPicked([]); void qc.invalidateQueries({ queryKey: ["mail-queue"] }); },
  });
  const toggle = (id: string) => setPicked(picked.includes(id) ? picked.filter((x) => x !== id) : [...picked, id]);
  return (
    <Card className="overflow-x-auto">
      <CardTitle>{t("email.queue.title")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("email.queue.hint")}</p>
      {q.isPending && <Spinner />}
      {(q.isError || act.isError) && <ErrorAlert error={q.error ?? act.error} />}
      {q.data && (
        <>
          <div className="mb-3 flex flex-wrap gap-2">
            <Button variant="ghost" onClick={() => void qc.invalidateQueries({ queryKey: ["mail-queue"] })}>{t("email.queue.refresh")}</Button>
            <Button variant="ghost" disabled={act.isPending || q.data.items.length === 0} onClick={() => act.mutate({ action: "flush_all" })}>{t("email.queue.flushAll")}</Button>
            <Button variant="ghost" disabled={act.isPending || picked.length === 0} onClick={() => act.mutate({ action: "flush", ids: picked })}>{t("email.queue.flush")}</Button>
            <Button variant="ghost" disabled={act.isPending || picked.length === 0} onClick={() => window.confirm(t("email.queue.confirmDelete", { count: picked.length })) && act.mutate({ action: "delete", ids: picked })}>{t("email.queue.delete")}</Button>
            <Button variant="ghost" disabled={act.isPending || q.data.items.length === 0} onClick={() => window.confirm(t("email.queue.confirmDeleteAll")) && act.mutate({ action: "delete_all" })}>{t("email.queue.deleteAll")}</Button>
          </div>
          <table className="w-full text-left text-sm">
            <thead className="text-slate-500">
              <tr><th />{["id", "queue", "arrived", "size", "from", "to"].map((k) => <th key={k} className="py-2 pr-4 font-medium">{t(`email.queue.col.${k}`)}</th>)}</tr>
            </thead>
            <tbody>
              {q.data.items.map((m) => (
                <tr key={m.id} className="border-t border-slate-200 align-top dark:border-slate-800">
                  <td className="py-2 pr-2"><input type="checkbox" aria-label={m.id} checked={picked.includes(m.id)} onChange={() => toggle(m.id)} /></td>
                  <td className="py-2 pr-4 font-mono">{m.id}</td>
                  <td className="py-2 pr-4">{m.queue}</td>
                  <td className="whitespace-nowrap py-2 pr-4">{new Date(m.arrived).toLocaleString()}</td>
                  <td className="py-2 pr-4">{Math.ceil(m.size / 1024)} KB</td>
                  <td className="py-2 pr-4 break-all">{m.sender || "-"}</td>
                  <td className="py-2 pr-4">
                    {m.recipients.map((r) => (
                      <div key={r.address} className="break-all">{r.address}{r.reason && <span className="block text-xs text-slate-500">{r.reason}</span>}</div>
                    ))}
                  </td>
                </tr>
              ))}
              {q.data.items.length === 0 && <tr><td colSpan={7} className="py-4 text-slate-500">{t("email.queue.empty")}</td></tr>}
            </tbody>
          </table>
          {q.data.items.length >= q.data.limit && <p className="mt-2 text-sm text-slate-500">{t("email.queue.limit", { n: q.data.limit })}</p>}
        </>
      )}
    </Card>
  );
}
