// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";

import { Badge } from "@/components/ui/badge";
import { SYSTEM_ROLES } from "@/lib/system-roles";

/** What each system role may do, shown beside the member list. */
export function RoleDescriptions() {
  return (
    <section
      aria-labelledby="system-roles-title"
      className="rounded-xl border border-border bg-card p-5"
    >
      <h3
        id="system-roles-title"
        className="text-sm font-semibold text-foreground"
      >
        System roles
      </h3>
      <p className="mt-1 text-sm text-muted-foreground">
        Every member holds at least one of these roles. Custom roles can add
        narrower sets of permissions.
      </p>
      <dl className="mt-4 grid gap-4 sm:grid-cols-2">
        {SYSTEM_ROLES.map((role) => (
          <div key={role.name} className="space-y-1.5">
            <dt>
              <Badge variant="secondary" textOnly>
                {role.label}
              </Badge>
            </dt>
            <dd className="text-sm text-muted-foreground">
              {role.description}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
