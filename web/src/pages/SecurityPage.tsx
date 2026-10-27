import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import QRCode from "qrcode";
import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api, unwrap } from "../api/client";
import { errorKey, useMe } from "../auth";
import { Alert, Button, Card, CardTitle, Field, Input } from "../components/ui";

function ErrorAlert({ error }: { error: unknown }) {
  const { t } = useTranslation();
  if (!error) return null;
  const detail = error instanceof ApiError ? error.problem?.errors?.[0]?.message : undefined;
  return <Alert>{detail ?? t(`errors.${errorKey(error)}`, { defaultValue: t("errors.unknown") })}</Alert>;
}

function ChangePassword({ forced }: { forced: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [mismatch, setMismatch] = useState(false);
  const change = useMutation({
    mutationFn: () => unwrap(api.POST("/me/password", { body: { current_password: current, new_password: next } })),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      setRepeat("");
      void qc.invalidateQueries({ queryKey: ["me"] });
      void qc.invalidateQueries({ queryKey: ["sessions"] });
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    setMismatch(next !== repeat);
    if (next === repeat) change.mutate();
  }

  return (
    <Card>
      <CardTitle>{t("security.password.title")}</CardTitle>
      {forced && <div className="mb-4"><Alert kind="info">{t("security.forcedPassword")}</Alert></div>}
      <form onSubmit={submit} className="max-w-md space-y-4">
        <Field id="current" label={t("security.password.current")}>
          <Input id="current" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field id="new" label={t("security.password.new")}>
          <Input id="new" type="password" autoComplete="new-password" minLength={10} required value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
        <Field id="repeat" label={t("security.password.repeat")} error={mismatch ? t("security.password.mismatch") : undefined}>
          <Input id="repeat" type="password" autoComplete="new-password" required aria-invalid={mismatch} value={repeat} onChange={(e) => setRepeat(e.target.value)} />
        </Field>
        <ErrorAlert error={change.error} />
        {change.isSuccess && <Alert kind="success">{t("security.password.changed")}</Alert>}
        <Button type="submit" disabled={change.isPending}>{t("common.save")}</Button>
      </form>
    </Card>
  );
}

function TwoFactor({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qr, setQr] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [recovery, setRecovery] = useState<string[] | null>(null);

  useEffect(() => {
    if (setup) void QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 200 }).then(setQr);
  }, [setup]);

  const begin = useMutation({ mutationFn: () => unwrap(api.POST("/me/2fa/setup")), onSuccess: setSetup });
  const confirm = useMutation({
    mutationFn: () => unwrap(api.POST("/me/2fa/confirm", { body: { code } })),
    onSuccess: (res) => {
      setRecovery(res.recovery_codes);
      setSetup(null);
      setCode("");
    },
  });
  const disable = useMutation({
    mutationFn: () => unwrap(api.POST("/me/2fa/disable", { body: { password } })),
    onSuccess: () => {
      setPassword("");
      void qc.invalidateQueries({ queryKey: ["me"] });
    },
  });

  if (recovery) {
    return (
      <Card>
        <CardTitle>{t("security.twofa.recoveryTitle")}</CardTitle>
        <p className="mb-4 text-sm">{t("security.twofa.recoveryHelp")}</p>
        <ul className="mb-4 grid max-w-sm grid-cols-2 gap-2 font-mono text-sm">
          {recovery.map((c) => <li key={c} className="rounded bg-slate-100 px-2 py-1 dark:bg-slate-800">{c}</li>)}
        </ul>
        <Button onClick={() => { setRecovery(null); void qc.invalidateQueries({ queryKey: ["me"] }); }}>
          {t("security.twofa.recoveryDone")}
        </Button>
      </Card>
    );
  }

  return (
    <Card>
      <CardTitle>{t("security.twofa.title")}</CardTitle>
      {enabled ? (
        <form onSubmit={(e) => { e.preventDefault(); disable.mutate(); }} className="max-w-md space-y-4">
          <Alert kind="success">{t("security.twofa.enabled")}</Alert>
          <p className="text-sm">{t("security.twofa.disableHelp")}</p>
          <Field id="disable-pw" label={t("login.password")}>
            <Input id="disable-pw" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          <ErrorAlert error={disable.error} />
          <Button type="submit" variant="danger" disabled={disable.isPending}>{t("security.twofa.disable")}</Button>
        </form>
      ) : setup ? (
        <form onSubmit={(e) => { e.preventDefault(); confirm.mutate(); }} className="max-w-md space-y-4">
          <p className="text-sm">{t("security.twofa.scan")}</p>
          {qr && <img src={qr} alt="QR code" width={200} height={200} className="rounded bg-white" />}
          <code className="block break-all rounded bg-slate-100 px-2 py-1 text-sm dark:bg-slate-800">{setup.secret}</code>
          <Field id="totp" label={t("security.twofa.confirm")}>
            <Input id="totp" autoComplete="one-time-code" inputMode="numeric" required value={code} onChange={(e) => setCode(e.target.value)} />
          </Field>
          <ErrorAlert error={confirm.error} />
          <div className="flex gap-2">
            <Button type="submit" disabled={confirm.isPending}>{t("security.twofa.activate")}</Button>
            <Button type="button" variant="secondary" onClick={() => setSetup(null)}>{t("common.cancel")}</Button>
          </div>
        </form>
      ) : (
        <div className="space-y-4">
          <p className="text-sm">{t("security.twofa.disabled")}</p>
          <ErrorAlert error={begin.error} />
          <Button onClick={() => begin.mutate()} disabled={begin.isPending}>{t("security.twofa.setup")}</Button>
        </div>
      )}
    </Card>
  );
}

function Sessions() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: () => unwrap(api.GET("/me/sessions")) });
  const revoke = useMutation({
    mutationFn: (id: string) => unwrap(api.DELETE("/me/sessions/{id}", { params: { path: { id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  return (
    <Card>
      <CardTitle>{t("security.sessions.title")}</CardTitle>
      <ErrorAlert error={sessions.error ?? revoke.error} />
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-slate-500">
            <tr>
              <th className="py-2 pr-4 font-medium">{t("security.sessions.ip")}</th>
              <th className="py-2 pr-4 font-medium">{t("security.sessions.device")}</th>
              <th className="py-2 pr-4 font-medium">{t("security.sessions.lastSeen")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {sessions.data?.items.map((s) => (
              <tr key={s.id} className="border-t border-slate-200 dark:border-slate-800">
                <td className="py-2 pr-4 font-mono">{s.ip}</td>
                <td className="max-w-xs truncate py-2 pr-4" title={s.user_agent}>{s.user_agent}</td>
                <td className="py-2 pr-4">{new Date(s.last_seen_at).toLocaleString()}</td>
                <td className="py-2 text-right">
                  {s.current ? (
                    <span className="text-xs text-slate-500">{t("common.current")}</span>
                  ) : (
                    <Button variant="ghost" onClick={() => revoke.mutate(s.id)} disabled={revoke.isPending}>
                      {t("security.sessions.revoke")}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function SecurityPage() {
  const { t } = useTranslation();
  const { data: me } = useMe();
  if (!me) return null;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("security.title")}</h1>
      <ChangePassword forced={me.must_change_password} />
      {!me.must_change_password && (
        <>
          <TwoFactor enabled={me.totp_enabled} />
          <Sessions />
        </>
      )}
    </div>
  );
}
