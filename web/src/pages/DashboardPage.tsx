import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { useMe } from "../auth";
import { Alert, Card } from "../components/ui";

export function DashboardPage() {
  const { t } = useTranslation();
  const { data: me } = useMe();
  if (!me) return null;
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">{t("dashboard.welcome", { name: me.username })}</h1>
      {!me.totp_enabled && (
        <Alert kind="info">
          {t("dashboard.enable2fa")}{" "}
          <Link to="/account/security" className="font-medium underline">{t("dashboard.enable2faLink")}</Link>
        </Alert>
      )}
      <Card>
        <p className="text-sm text-slate-600 dark:text-slate-400">{t("dashboard.intro")}</p>
      </Card>
    </div>
  );
}
