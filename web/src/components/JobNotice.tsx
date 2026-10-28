import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import { Alert } from "./ui";

const done = (status?: string) => !!status && ["succeeded", "failed", "canceled"].includes(status);

/** Polls a job until it finishes, then calls onDone once. */
export function useJob(jobId: string | undefined, onDone: () => void) {
  const job = useQuery({
    queryKey: ["jobs", jobId],
    queryFn: () => unwrap(api.GET("/jobs/{id}", { params: { path: { id: jobId! } } })),
    enabled: !!jobId,
    refetchInterval: (q) => (done(q.state.data?.status) ? false : 1000),
  });
  const finished = done(job.data?.status);
  useEffect(() => {
    if (finished) onDone();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finished]);
  return job.data;
}

/** Shows how the job of the last change is doing. */
export function JobNotice({ jobId, onDone }: { jobId?: string; onDone: () => void }) {
  const { t } = useTranslation();
  const job = useJob(jobId, onDone);
  if (!jobId || !job) return null;
  if (job.status === "succeeded") return <Alert kind="success">{t("job.succeeded")}</Alert>;
  if (job.status === "failed") return <Alert>{t("job.failed", { error: job.error ?? "" })}</Alert>;
  return <Alert kind="info">{t("job.running")} {job.progress > 0 && `${job.progress}%`}</Alert>;
}
