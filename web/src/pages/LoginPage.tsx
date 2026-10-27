import { useQueryClient } from "@tanstack/react-query";
import { Navigate, useNavigate } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, setCsrfToken, unwrap } from "../api/client";
import { errorKey, useMe } from "../auth";
import { Alert, Button, Card, Field, Input } from "../components/ui";

export function LoginPage() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const me = useMe();
  const [step, setStep] = useState<"password" | "mfa">("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (me.data) return <Navigate to="/" />;

  async function finish() {
    await qc.invalidateQueries({ queryKey: ["me"] });
    await navigate({ to: "/" });
  }

  async function onPassword(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const res = await unwrap(api.POST("/auth/login", { body: { username, password } }));
      setCsrfToken(res.csrf_token);
      setPassword("");
      if (res.mfa_required) setStep("mfa");
      else await finish();
    } catch (err) {
      setError(errorKey(err));
    } finally {
      setBusy(false);
    }
  }

  async function onCode(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await unwrap(api.POST("/auth/2fa/verify", { body: { code } }));
      await finish();
    } catch (err) {
      setError(errorKey(err));
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <h1 className="text-2xl font-bold text-brand">{t("app.name")}</h1>
        <p className="mb-6 text-sm text-slate-500">{t("login.subtitle")}</p>
        {error && (
          <div className="mb-4">
            <Alert>{t(`errors.${error}`, { defaultValue: t("errors.unknown") })}</Alert>
          </div>
        )}
        {step === "password" ? (
          <form onSubmit={onPassword} className="space-y-4">
            <Field id="username" label={t("login.username")}>
              <Input id="username" autoComplete="username" autoFocus required
                value={username} onChange={(e) => setUsername(e.target.value)} />
            </Field>
            <Field id="password" label={t("login.password")}>
              <Input id="password" type="password" autoComplete="current-password" required
                value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <Button type="submit" className="w-full" disabled={busy}>{t("login.submit")}</Button>
          </form>
        ) : (
          <form onSubmit={onCode} className="space-y-4">
            <h2 className="font-semibold">{t("login.mfaTitle")}</h2>
            <p className="text-sm text-slate-500">{t("login.mfaHelp")}</p>
            <Field id="code" label={t("login.code")}>
              <Input id="code" autoComplete="one-time-code" inputMode="text" autoFocus required
                value={code} onChange={(e) => setCode(e.target.value)} />
            </Field>
            <Button type="submit" className="w-full" disabled={busy}>{t("login.verify")}</Button>
            <Button type="button" variant="ghost" className="w-full"
              onClick={() => { setStep("password"); setError(""); }}>
              {t("login.back")}
            </Button>
          </form>
        )}
      </Card>
    </div>
  );
}
