// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  canCreateCredentials,
  canViewAudit,
  canViewCredentials,
  canViewIntegrations,
  canViewAlerts,
  canViewNotifications,
} from "@/lib/authz";
import {
  DEPLOYMENT_CREDENTIAL_ALIASES,
  DNS_CREDENTIAL_ALIASES,
} from "@/lib/app-search-aliases";
import {
  type AppSearchContext,
  type AppSearchItem,
  createAppSearchItem,
} from "@/lib/app-search-types";

export function getOperationsSearchItems({
  isFeatureEnabled,
  isSuperAdmin,
  user,
}: AppSearchContext): AppSearchItem[] {
  const items: AppSearchItem[] = [];

  if (canViewAudit(user, isSuperAdmin) && isFeatureEnabled("AUDIT_LOGS")) {
    items.push(
      createAppSearchItem(
        "Audit logs",
        "Search security and administration events.",
        "/settings/audit-logs",
        "Operations",
        ["events", "activity", "security"],
      ),
    );
  }

  if (canViewAlerts(user) && isFeatureEnabled("ALERTS")) {
    // Escalations exist only while integrations are on, as in the sidebar.
    const hasEscalations = isFeatureEnabled("INTEGRATIONS");
    items.push(
      createAppSearchItem(
        hasEscalations ? "Alerts & escalations" : "Alerts",
        hasEscalations
          ? "Review active incidents and escalation state."
          : "Review alerts from your certificates.",
        "/incidents",
        "Operations",
        ["incidents", "alerts", "notifications"],
      ),
    );
  }

  if (canViewNotifications(user)) {
    items.push(
      createAppSearchItem(
        "Notifications",
        "Review system notifications.",
        "/incidents/system-notifications",
        "Operations",
        ["messages", "delivery", "system"],
      ),
    );
  }

  // Integrations: one section, one category per entry. Every alias list keeps
  // the word "credential" even though the UI has stopped saying it - people who
  // learned the old vocabulary still type it into the palette.
  if (canViewIntegrations(user)) {
    items.push(
      createAppSearchItem(
        "Apps",
        "Send alerts and tickets to Slack, Teams, PagerDuty, or ServiceNow.",
        "/integrations/apps",
        "Integrations",
        [
          "integrations",
          "apps",
          "slack",
          "teams",
          "pagerduty",
          "servicenow",
          "webhook",
          "notifications",
        ],
      ),
    );
  }

  if (canViewCredentials(user) && isFeatureEnabled("CREDENTIALS_MANAGEMENT")) {
    items.push(
      createAppSearchItem(
        "DNS Providers",
        "DNS accounts used to prove domain control during DNS-01 validation.",
        "/integrations/dns",
        "Integrations",
        [
          "dns provider",
          "dns credential",
          "dns-01",
          "credentials",
          "secrets",
          ...DNS_CREDENTIAL_ALIASES,
        ],
      ),
    );

    if (isFeatureEnabled("CERTIFICATE_DEPLOYMENT")) {
      items.push(
        createAppSearchItem(
          "Deployment Targets",
          "Destinations CertPing delivers issued certificates to.",
          "/integrations/deployment-targets",
          "Integrations",
          [
            "deployment target",
            "deployment credential",
            "credentials",
            "secrets",
            ...DEPLOYMENT_CREDENTIAL_ALIASES,
          ],
        ),
      );
    }

    if (canCreateCredentials(user)) {
      items.push(
        createAppSearchItem(
          "Add Connection",
          "Connect a DNS provider or add a deployment target.",
          "/integrations/connections/add",
          "Integrations",
          [
            "add connection",
            "new connection",
            "add credential",
            "new credential",
            "create credential",
            "provider credential",
          ],
        ),
      );

      if (isFeatureEnabled("DNS_CREDENTIALS")) {
        items.push(
          createAppSearchItem(
            "Connect DNS Provider",
            "Connect a DNS account for DNS-01 domain validation.",
            "/integrations/connections/add?type=DNS",
            "Integrations",
            ["add dns", "connect dns", ...DNS_CREDENTIAL_ALIASES],
          ),
        );
      }

      if (isFeatureEnabled("CERTIFICATE_DEPLOYMENT")) {
        items.push(
          createAppSearchItem(
            "Add Deployment Target",
            "Add a destination for certificate delivery.",
            "/integrations/connections/add?type=DEPLOYMENT",
            "Integrations",
            [
              "deploy credential",
              "add deployment",
              ...DEPLOYMENT_CREDENTIAL_ALIASES,
            ],
          ),
        );
      }
    }
  }

  return items;
}
