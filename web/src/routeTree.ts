import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
} from "@tanstack/react-router";
import { rootRouteComponent } from "@/routes/root";
import { DashboardPage } from "@/routes/index";
import { IntentsPage } from "@/routes/intents.index";
import { IntentDetailPage } from "@/routes/intents.$intentId";
import { PasskeysPage } from "@/routes/passkeys";
import { ChatPage } from "@/routes/chat";
import { TransactionsPage } from "@/routes/transactions";
import { SettingsPage } from "@/routes/settings";

const rootRoute = createRootRoute({ component: rootRouteComponent });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: DashboardPage,
});

const intentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/intents",
  component: Outlet,
});

const intentsIndexRoute = createRoute({
  getParentRoute: () => intentsRoute,
  path: "/",
  component: IntentsPage,
});

const intentDetailRoute = createRoute({
  getParentRoute: () => intentsRoute,
  path: "$intentId",
  component: IntentDetailPage,
});

const passkeysRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/passkeys",
  component: PasskeysPage,
});

const chatRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/chat",
  component: ChatPage,
});

const transactionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/transactions",
  component: TransactionsPage,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  intentsRoute.addChildren([intentsIndexRoute, intentDetailRoute]),
  passkeysRoute,
  chatRoute,
  transactionsRoute,
  settingsRoute,
]);

export const router = createRouter({ routeTree });
