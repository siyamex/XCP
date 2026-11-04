import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
import { AppLayout } from "./components/AppLayout";
import { AccountCreatePage, AccountDetailPage, AccountsPage } from "./pages/AccountsPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DnsSettingsPage, ZonePage, ZonesPage } from "./pages/DnsPage";
import { MyDomainsPage } from "./pages/DomainsPage";
import { FeatureListsPage } from "./pages/FeatureListsPage";
import { LoginPage } from "./pages/LoginPage";
import { PackageEditPage, PackagesPage } from "./pages/PackagesPage";
import { SecurityPage } from "./pages/SecurityPage";
import { SslPage } from "./pages/SslPage";
import { DatabasesPage } from "./pages/DatabasesPage";
import { EmailPage } from "./pages/EmailPage";
import { FilesPage } from "./pages/FilesPage";
import { CronPage } from "./pages/CronPage";
import { BackupsPage } from "./pages/BackupsPage";
import { FtpPage } from "./pages/FtpPage";
import { FirewallPage } from "./pages/FirewallPage";
import { ResellersPage } from "./pages/ResellerPages";
import { SettingsPage } from "./pages/SettingsPage";
import { JobsPage, ServicesPage, SessionsPage } from "./pages/ServerPages";
import { StatsPage } from "./pages/StatsPage";

const rootRoute = createRootRoute({ component: Outlet });

const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "/login", component: LoginPage });

// Pathless layout: every child needs a logged-in user (AppLayout redirects otherwise).
const appRoute = createRoute({ getParentRoute: () => rootRoute, id: "app", component: AppLayout });
const dashboardRoute = createRoute({ getParentRoute: () => appRoute, path: "/", component: DashboardPage });
const securityRoute = createRoute({ getParentRoute: () => appRoute, path: "/account/security", component: SecurityPage });

const packagesRoute = createRoute({ getParentRoute: () => appRoute, path: "/packages", component: PackagesPage });
const packageEditRoute = createRoute({ getParentRoute: () => appRoute, path: "/packages/$packageId", component: PackageEditPage });
const accountsRoute = createRoute({ getParentRoute: () => appRoute, path: "/accounts", component: AccountsPage });
const accountNewRoute = createRoute({ getParentRoute: () => appRoute, path: "/accounts/new", component: AccountCreatePage });
const accountRoute = createRoute({ getParentRoute: () => appRoute, path: "/accounts/$accountId", component: AccountDetailPage });
const featureListsRoute = createRoute({ getParentRoute: () => appRoute, path: "/feature-lists", component: FeatureListsPage });
const domainsRoute = createRoute({ getParentRoute: () => appRoute, path: "/domains", component: MyDomainsPage });
const zonesRoute = createRoute({ getParentRoute: () => appRoute, path: "/dns", component: ZonesPage });
const dnsSettingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/dns/settings", component: DnsSettingsPage });
const zoneRoute = createRoute({ getParentRoute: () => appRoute, path: "/dns/$zoneId", component: ZonePage });
const sslRoute = createRoute({ getParentRoute: () => appRoute, path: "/ssl", component: SslPage });
const databasesRoute = createRoute({ getParentRoute: () => appRoute, path: "/databases", component: DatabasesPage });
const emailRoute = createRoute({ getParentRoute: () => appRoute, path: "/email", component: EmailPage });
const filesRoute = createRoute({ getParentRoute: () => appRoute, path: "/files", component: FilesPage });
const ftpRoute = createRoute({ getParentRoute: () => appRoute, path: "/ftp", component: FtpPage });
const cronRoute = createRoute({ getParentRoute: () => appRoute, path: "/cron", component: CronPage });
const statsRoute = createRoute({ getParentRoute: () => appRoute, path: "/stats", component: StatsPage });
const backupsRoute = createRoute({ getParentRoute: () => appRoute, path: "/backups", component: BackupsPage });
const servicesRoute = createRoute({ getParentRoute: () => appRoute, path: "/services", component: ServicesPage });
const jobsRoute = createRoute({ getParentRoute: () => appRoute, path: "/jobs", component: JobsPage });
const settingsRoute = createRoute({ getParentRoute: () => appRoute, path: "/settings", component: SettingsPage });
const firewallRoute = createRoute({ getParentRoute: () => appRoute, path: "/firewall", component: FirewallPage });
const resellersRoute = createRoute({ getParentRoute: () => appRoute, path: "/resellers", component: ResellersPage });
const sessionsRoute = createRoute({ getParentRoute: () => appRoute, path: "/sessions", component: SessionsPage });

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([
    dashboardRoute, securityRoute, packagesRoute, packageEditRoute, featureListsRoute,
    accountsRoute, accountNewRoute, accountRoute, domainsRoute,
    zonesRoute, dnsSettingsRoute, zoneRoute, sslRoute, databasesRoute, emailRoute, filesRoute, ftpRoute, cronRoute, statsRoute, backupsRoute, servicesRoute, jobsRoute, sessionsRoute, resellersRoute, firewallRoute, settingsRoute,
  ]),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
