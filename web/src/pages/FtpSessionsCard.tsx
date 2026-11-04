import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, unwrap } from "../api/client";
import { ErrorAlert } from "../components/ErrorAlert";
import { Button, Card, CardTitle } from "../components/ui";

/** Who is connected to the account's FTP logins right now, with a way to disconnect. */
export function FtpSessionsCard({ accountId }: { accountId: string }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const key = ["ftp-sessions", accountId];
  const q = useQuery({
    queryKey: key,
    queryFn: () => unwrap(api.GET("/accounts/{id}/ftp/sessions", { params: { path: { id: accountId } } })),
    refetchInterval: 10000,
    retry: false,
  });
  const end = useMutation({
    mutationFn: (pid: number) => unwrap(api.DELETE("/accounts/{id}/ftp/sessions/{pid}", { params: { path: { id: accountId, pid } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: key }),
  });
  // The FTP server may not be installed or the person may not be allowed to see it: then show nothing.
  if (q.isError || !q.data) return null;
  return (
    <Card className="overflow-x-auto p-0">
      <div className="px-4 pt-4"><CardTitle>{t("ftp.sessions.title")}</CardTitle></div>
      {end.isError && <div className="px-4"><ErrorAlert error={end.error} /></div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-slate-500 dark:border-slate-800">
          <tr>{["login", "from", "connected", "doing", ""].map((k) => <th key={k} className="px-4 py-3 font-medium">{k && t(`ftp.sessions.${k}`)}</th>)}</tr>
        </thead>
        <tbody>
          {q.data.items.map((s) => (
            <tr key={s.pid} className="border-t border-slate-100 dark:border-slate-800">
              <td className="px-4 py-3 font-mono">{s.login}</td>
              <td className="px-4 py-3 font-mono">{s.peer}</td>
              <td className="px-4 py-3">{Math.floor(s.seconds / 60)} min</td>
              <td className="px-4 py-3">{s.file && s.file !== "-" ? `${s.state} ${s.file} ${s.percent}%` : s.state}</td>
              <td className="px-4 py-3 text-right">
                <Button variant="ghost" disabled={end.isPending} onClick={() => window.confirm(t("ftp.sessions.confirm", { login: s.login })) && end.mutate(s.pid)}>{t("ftp.sessions.end")}</Button>
              </td>
            </tr>
          ))}
          {q.data.items.length === 0 && <tr><td colSpan={5} className="px-4 py-6 text-center text-slate-500">{t("ftp.sessions.none")}</td></tr>}
        </tbody>
      </table>
    </Card>
  );
}
