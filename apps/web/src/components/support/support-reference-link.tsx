// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { cn } from "@/lib/utils";
import { EXTERNAL_LINK_PROPS, newGithubIssueHref } from "@/lib/support-links";

interface SupportReferenceParams {
  /**
   * Per-operation trace id. When present it is shown as the "Reference ID" and included in the
   * issue body. When absent (e.g. records created before correlation IDs were captured) a plain
   * "Report this issue" link is shown instead.
   */
  correlationId?: string | null;
  /** Issue title. */
  summary: string;
  /** Sanitized, user-facing error message to include in the issue (never raw system detail). */
  message?: string | null;
  /** Domain the failure relates to, included in the issue body. */
  domain?: string | null;
}

/**
 * Builds a link to a new issue in the project's GitHub repository with the title and the details
 * that are present, so a missing correlation ID simply yields an issue without a reference.
 */
export function buildSupportHref({
  correlationId,
  summary,
  message,
  domain,
}: SupportReferenceParams): string {
  const lines = [
    correlationId ? `Reference ID: ${correlationId}` : null,
    domain ? `Domain: ${domain}` : null,
    message ? `Message: ${message}` : null,
  ].filter((line): line is string => line !== null);
  return newGithubIssueHref(
    summary,
    lines.length > 0 ? lines.join("\n") : undefined,
  );
}

/**
 * Renders the support entry point for a failed operation. With a correlation ID it shows the
 * "Reference ID"; without one (legacy records) it degrades to a plain "Report this issue" link.
 * Both open a pre-filled GitHub issue with the domain and error message.
 */
export function SupportReferenceLink({
  correlationId,
  summary,
  message,
  domain,
  className,
}: SupportReferenceParams & { className?: string }) {
  const href = buildSupportHref({ correlationId, summary, message, domain });

  if (correlationId) {
    return (
      <div className={cn("space-y-1", className)}>
        <div className="text-xs text-muted-foreground">Reference ID</div>
        <a
          href={href}
          {...EXTERNAL_LINK_PROPS}
          className="font-mono text-xs break-all text-primary underline underline-offset-2 hover:no-underline"
        >
          {correlationId}
        </a>
        <p className="text-xs text-muted-foreground">
          Share this reference when you ask for help. Click it to open a
          pre-filled GitHub issue; remove anything private before you submit.
        </p>
      </div>
    );
  }

  return (
    <div className={cn("space-y-1", className)}>
      <a
        href={href}
        {...EXTERNAL_LINK_PROPS}
        className="text-xs font-medium text-primary underline underline-offset-2 hover:no-underline"
      >
        Report this issue on GitHub
      </a>
      <p className="text-xs text-muted-foreground">
        Opens a pre-filled GitHub issue.
      </p>
    </div>
  );
}
