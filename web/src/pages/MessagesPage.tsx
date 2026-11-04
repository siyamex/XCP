import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import type { components } from "../api/schema";
import { ErrorAlert } from "../components/ErrorAlert";
import { Alert, Button, Card, CardTitle, Field, Input, Spinner } from "../components/ui";
import { JobNotice } from "../components/JobNotice";

type Template = components["schemas"]["MessageTemplate"];

const areaClass = "w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm dark:border-slate-700 dark:bg-slate-900";

/** Email to customers for admins and resellers: the welcome message and a message to all (RSL-ACC-09, RSL-UI-03). */
export function MessagesPage() {
  const { t } = useTranslation();
  const q = useQuery({ queryKey: ["welcome"], queryFn: () => unwrap(api.GET("/messages/welcome")), retry: false });
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("messages.title")}</h1>
      {q.isPending && <Spinner />}
      {q.isError && <ErrorAlert error={q.error} />}
      {q.data && <Welcome initial={q.data} />}
      <Broadcast variables={q.data?.variables ?? []} />
    </div>
  );
}

function Variables({ list }: { list: string[] }) {
  const { t } = useTranslation();
  return <p className="text-sm text-slate-500">{t("messages.variables")} {list.map((v) => `{{${v}}}`).join("  ")}</p>;
}

function Welcome({ initial }: { initial: Template }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [subject, setSubject] = useState(initial.subject);
  const [body, setBody] = useState(initial.body);
  const save = useMutation({
    mutationFn: (v: { subject: string; body: string }) => unwrap(api.PUT("/messages/welcome", { body: v })),
    onSuccess: (r) => { setSubject(r.subject); setBody(r.body); void qc.invalidateQueries({ queryKey: ["welcome"] }); },
  });
  return (
    <Card>
      <CardTitle>{t("messages.welcome")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t(initial.custom ? "messages.welcomeCustom" : "messages.welcomeDefault")}</p>
      <form onSubmit={(e) => { e.preventDefault(); save.mutate({ subject, body }); }} className="space-y-3">
        <Field id="w-sub" label={t("messages.subject")}><Input id="w-sub" required value={subject} onChange={(e) => setSubject(e.target.value)} /></Field>
        <Field id="w-body" label={t("messages.body")}><textarea id="w-body" rows={8} required className={areaClass} value={body} onChange={(e) => setBody(e.target.value)} /></Field>
        <Variables list={initial.variables} />
        {save.isError && <ErrorAlert error={save.error} />}
        {save.isSuccess && <Alert kind="success">{t("messages.saved")}</Alert>}
        <div className="flex gap-2">
          <Button type="submit" disabled={save.isPending}>{t("common.save")}</Button>
          <Button type="button" variant="ghost" disabled={save.isPending} onClick={() => save.mutate({ subject: "", body: "" })}>{t("messages.reset")}</Button>
        </div>
      </form>
    </Card>
  );
}

function Broadcast({ variables }: { variables: string[] }) {
  const { t } = useTranslation();
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [jobId, setJobId] = useState<string>();
  const send = useMutation({
    mutationFn: () => unwrap(api.POST("/messages/broadcast", { body: { subject, body } })),
    onSuccess: (r) => { setJobId(r.job_id); setSubject(""); setBody(""); },
  });
  return (
    <Card>
      <CardTitle>{t("messages.broadcast")}</CardTitle>
      <p className="mb-3 text-sm text-slate-500">{t("messages.broadcastHint")}</p>
      <form
        onSubmit={(e) => { e.preventDefault(); if (window.confirm(t("messages.confirmBroadcast"))) send.mutate(); }}
        className="space-y-3"
      >
        <Field id="b-sub" label={t("messages.subject")}><Input id="b-sub" required value={subject} onChange={(e) => setSubject(e.target.value)} /></Field>
        <Field id="b-body" label={t("messages.body")}><textarea id="b-body" rows={8} required className={areaClass} value={body} onChange={(e) => setBody(e.target.value)} /></Field>
        <Variables list={variables} />
        {send.isError && <ErrorAlert error={send.error} />}
        {jobId && <JobNotice jobId={jobId} onDone={() => undefined} />}
        <Button type="submit" disabled={send.isPending}>{t("messages.send")}</Button>
      </form>
    </Card>
  );
}
