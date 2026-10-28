import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
import { AppLayout } from "./components/AppLayout";
import { AccountCreatePage, AccountDetailPage, AccountsPage } from "./pages/AccountsPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FeatureListsPage } from "./pages/FeatureListsPage";
import { LoginPage } from "./pages/LoginPage";
import { PackageEditPage, PackagesPage } from "./pages/PackagesPage";
import { SecurityPage } from "./pages/SecurityPage";

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

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([
    dashboardRoute, securityRoute, packagesRoute, packageEditRoute, featureListsRoute,
    accountsRoute, accountNewRoute, accountRoute,
  ]),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
