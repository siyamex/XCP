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

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([
    dashboardRoute, securityRoute, packagesRoute, packageEditRoute, featureListsRoute,
    accountsRoute, accountNewRoute, accountRoute, domainsRoute,
    zonesRoute, dnsSettingsRoute, zoneRoute, sslRoute,
  ]),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
