import { Link, Navigate, Outlet, useRouterState } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useLogout, useMe } from "../auth";
import { getTheme, setTheme, type Theme } from "../lib/theme";
import { cn } from "../lib/cn";
import { Button, Spinner } from "./ui";

type NavItem = { key: string; to?: string };

// Items without "to" are planned features (P1+), shown so the layout is complete.
const menus: Record<string, NavItem[]> = {
  admin: [
    { key: "dashboard", to: "/" },
    { key: "accounts" }, { key: "packages" }, { key: "resellers" },
    { key: "dns" }, { key: "services" }, { key: "settings" },
    { key: "security", to: "/account/security" },
  ],
  reseller: [
    { key: "dashboard", to: "/" },
    { key: "customers" }, { key: "packages" }, { key: "dns" },
    { key: "security", to: "/account/security" },
  ],
  user: [
    { key: "dashboard", to: "/" },
    { key: "domains" }, { key: "email" }, { key: "databases" }, { key: "files" },
    { key: "ssl" }, { key: "backups" },
    { key: "security", to: "/account/security" },
  ],
};

export function AppLayout() {
  const { t } = useTranslation();
  const me = useMe();
  const logout = useLogout();
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [theme, setThemeState] = useState<Theme>(getTheme());

  if (me.isPending) return <Spinner />;
  if (!me.data) return <Navigate to="/login" />;
  if (me.data.must_change_password && path !== "/account/security") {
    return <Navigate to="/account/security" />;
  }

  const items = menus[me.data.role] ?? menus.user!;
  const nextTheme: Record<Theme, Theme> = { system: "light", light: "dark", dark: "system" };

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 border-r border-slate-200 bg-white p-4 md:block dark:border-slate-800 dark:bg-slate-900">
        <div className="mb-6 px-2 text-lg font-bold text-brand">{t("app.name")}</div>
        <nav className="space-y-1">
          {items.map((item) =>
            item.to ? (
              <Link
                key={item.key}
                to={item.to}
                className="block rounded-md px-3 py-2 text-sm hover:bg-slate-100 dark:hover:bg-slate-800"
                activeProps={{ className: "bg-slate-100 font-medium dark:bg-slate-800" }}
                activeOptions={{ exact: true }}
              >
                {t(`nav.${item.key}`)}
              </Link>
            ) : (
              <span
                key={item.key}
                aria-disabled="true"
                className="flex items-center justify-between rounded-md px-3 py-2 text-sm text-slate-400 dark:text-slate-600"
              >
                {t(`nav.${item.key}`)}
                <span className="rounded bg-slate-100 px-1.5 text-xs dark:bg-slate-800">{t("common.comingSoon")}</span>
              </span>
            ),
          )}
        </nav>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-end gap-3 border-b border-slate-200 bg-white px-4 py-3 md:px-6 dark:border-slate-800 dark:bg-slate-900">
          <span className="mr-auto font-bold text-brand md:hidden">{t("app.name")}</span>
          <span className="hidden text-sm sm:inline">
            <span className="font-medium">{me.data.username}</span>{" "}
            <span className={cn("rounded px-1.5 py-0.5 text-xs", "bg-slate-100 dark:bg-slate-800")}>
              {t(`role.${me.data.role}`)}
            </span>
          </span>
          <Button
            variant="ghost"
            onClick={() => {
              const n = nextTheme[theme];
              setTheme(n);
              setThemeState(n);
            }}
          >
            {t(`topbar.theme.${theme}`)}
          </Button>
          <Button variant="secondary" onClick={() => logout.mutate()} disabled={logout.isPending}>
            {t("topbar.logout")}
          </Button>
        </header>
        {/* Small screens: the sidebar is hidden, so show the available pages as a scrollable row. */}
        <nav className="flex gap-1 overflow-x-auto border-b border-slate-200 bg-white px-4 py-2 md:hidden dark:border-slate-800 dark:bg-slate-900">
          {items.filter((item) => item.to).map((item) => (
            <Link
              key={item.key}
              to={item.to}
              className="whitespace-nowrap rounded-md px-3 py-1.5 text-sm"
              activeProps={{ className: "bg-slate-100 font-medium dark:bg-slate-800" }}
              activeOptions={{ exact: true }}
            >
              {t(`nav.${item.key}`)}
            </Link>
          ))}
        </nav>
        <main className="mx-auto w-full max-w-5xl flex-1 p-4 md:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
