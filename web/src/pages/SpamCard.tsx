import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";

type Spam = components["schemas"]["MailboxSpam"];
type Mailbox = { id: string; address: string };

const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";
const areaClass = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 font-mono text-sm dark:border-slate-700 dark:bg-slate-900";
const lines = (s: string) => s.split(/[\s,]+/).filter(Boolean);

/** The spam filter of a mailbox: on or off, how strict, Junk or delete, allow and block lists (USR-MAIL-08). */
export function SpamCard({ mailboxes, onStarted }: { mailboxes: Mailbox[]; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [id, setId] = useState("");
  const box = mailboxes.find((m) => m.id === id) ?? mailboxes[0];
  const q = useQuery({
    queryKey: ["mailbox-spam", box?.id],
    queryFn: () => unwrap(api.GET("/mailboxes/{id}/spam", { params: { path: { id: box!.id } } })),
    enabled: !!box,
    retry: false,
  });
  // 403 when the package has no spam filter feature: the section is hidden then.
  if (!box || q.isError) return null;
  return (
    <Card>
      <CardTitle>{t("email.spam.title")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("email.spam.hint")}</p>
      <Field id="sp-box" label={t("email.spam.mailbox")}>
        <select id="sp-box" className={selectClass} value={box.id} onChange={(e) => setId(e.target.value)}>
          {mailboxes.map((m) => <option key={m.id} value={m.id}>{m.address}</option>)}
        </select>
      </Field>
      {q.isPending && <Spinner />}
      {q.data && <SpamForm key={box.id} mailboxId={box.id} initial={q.data} onStarted={onStarted} />}
    </Card>
  );
}

function SpamForm({ mailboxId, initial, onStarted }: { mailboxId: string; initial: Spam; onStarted: (r: { job_id?: string }) => void }) {
  const { t } = useTranslation();
  const [enabled, setEnabled] = useState(initial.enabled);
  const [threshold, setThreshold] = useState(String(initial.threshold));
  const [action, setAction] = useState(initial.action);
  const [allow, setAllow] = useState(initial.allow.join("\n"));
  const [block, setBlock] = useState(initial.block.join("\n"));
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/mailboxes/{id}/spam", {
      params: { path: { id: mailboxId } },
      body: { enabled, threshold: Number(threshold), action, allow: lines(allow), block: lines(block) },
    })),
    onSuccess: onStarted,
  });
  return (
    <form onSubmit={(e) => { e.preventDefault(); save.mutate(); }} className="mt-4 space-y-4">
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />{t("email.spam.enabled")}</label>
      <div className="grid gap-4 md:grid-cols-2">
        <Field id="sp-th" label={t("email.spam.threshold")}><Input id="sp-th" inputMode="numeric" value={threshold} onChange={(e) => setThreshold(e.target.value)} /></Field>
        <Field id="sp-act" label={t("email.spam.action")}>
          <select id="sp-act" className={selectClass} value={action} onChange={(e) => setAction(e.target.value as Spam["action"])}>
            <option value="junk">{t("email.spam.junk")}</option>
            <option value="delete">{t("email.spam.delete")}</option>
          </select>
        </Field>
      </div>
      <p className="text-sm text-slate-500">{t("email.spam.thresholdHint")}</p>
      <div className="grid gap-4 md:grid-cols-2">
        <Field id="sp-allow" label={t("email.spam.allow")}><textarea id="sp-allow" rows={4} className={areaClass} placeholder="friend@example.com&#10;*@partner.example" value={allow} onChange={(e) => setAllow(e.target.value)} /></Field>
        <Field id="sp-block" label={t("email.spam.block")}><textarea id="sp-block" rows={4} className={areaClass} placeholder="*@spam.example" value={block} onChange={(e) => setBlock(e.target.value)} /></Field>
      </div>
      {action === "delete" && <Alert kind="info">{t("email.spam.deleteWarning")}</Alert>}
      {save.isError && <ErrorAlert error={save.error} />}
      {save.isSuccess && <Alert kind="success">{t("email.spam.saved")}</Alert>}
      <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
    </form>
  );
}
