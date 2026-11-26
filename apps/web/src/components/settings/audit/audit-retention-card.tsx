// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useId, useRef, useState } from "react";
import {
  ArrowClockwiseIcon,
  CheckCircleIcon,
  HourglassMediumIcon,
  InfoIcon,
  WarningIcon,
  WarningOctagonIcon,
} from "@phosphor-icons/react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { DetailItem, DetailList } from "@/components/ui/detail-list";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SegmentedControl } from "@/components/ui/segmented-control";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import {
  useAuditRetention,
  useSetAuditRetention,
} from "@/hooks/data-retention";
import { useAuth } from "@/hooks/use-auth";
import {
  MAX_REASON_LENGTH,
  RETENTION_CHOICES,
  choiceForMonths,
  describeRetentionSave,
  formatMonth,
  formatRetentionPeriod,
  reasonLength,
  retentionStatus,
  validateMonths,
  validateReason,
  type RetentionChoice,
  type RetentionSaveCopy,
  type RetentionStatusTone,
} from "@/lib/audit-retention";
import {
  getAuditRetentionBounds,
  type AuditRetention,
} from "@/lib/backend/audit-retention";
import { getApiErrorMessage } from "@/lib/backend/common";
import { isAccessDeniedError } from "@/lib/http-errors";
import { cn, formatDateTime } from "@/lib/utils";

/**
 * Super-admin card for how long audit log entries are kept, platform-wide.
 * Every save confirms the period; nothing is deleted before the first
 * confirmation, and the first confirmation or a shortening deletes only after
 * a grace period. When deletion would start comes from the server.
 */
export function AuditRetentionCard() {
  const { isSuperAdmin } = useAuth();
  const query = useAuditRetention({ enabled: isSuperAdmin });
  const titleId = useId();

  if (!isSuperAdmin || isAccessDeniedError(query.error)) return null;

  return (
    <Card aria-labelledby={titleId} role="region">
      <CardHeader>
        <CardTitle id={titleId}>Audit log retention</CardTitle>
        <CardDescription>
          How long audit log entries are kept, for every organization. Whole
          months are deleted, so entries stay up to one month longer.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {query.data ? (
          <AuditRetentionSettings
            isRefreshing={query.isFetching}
            onRefresh={() => void query.refetch()}
            refreshFailed={query.isRefetchError}
            retention={query.data}
          />
        ) : query.isError ? (
          <Alert variant="destructive">
            <WarningOctagonIcon aria-hidden="true" />
            <AlertTitle>Couldn&apos;t load audit retention</AlertTitle>
            <AlertDescription className="space-y-3">
              <p>{getApiErrorMessage(query.error, "Please try again.")}</p>
              <Button
                size="sm"
                variant="outline"
                onClick={() => void query.refetch()}
              >
                <ArrowClockwiseIcon aria-hidden="true" />
                Try again
              </Button>
            </AlertDescription>
          </Alert>
        ) : (
          <div aria-busy="true" aria-label="Loading audit retention">
            <Skeleton className="h-16 w-full" />
            <Skeleton className="mt-4 h-24 w-full" />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

const STATUS_ICONS: Record<RetentionStatusTone, React.ReactNode> = {
  warning: <WarningIcon aria-hidden="true" />,
  info: <HourglassMediumIcon aria-hidden="true" />,
  success: <CheckCircleIcon aria-hidden="true" />,
};

function RetentionStatusBanner({ retention }: { retention: AuditRetention }) {
  const status = retentionStatus(retention);
  return (
    <Alert role="status" variant={status.tone} data-status={status.kind}>
      {STATUS_ICONS[status.tone]}
      <AlertTitle>{status.title}</AlertTitle>
      {status.details.length > 0 ? (
        <AlertDescription className="space-y-1">
          {status.details.map((detail) => (
            <p key={detail}>{detail}</p>
          ))}
        </AlertDescription>
      ) : null}
    </Alert>
  );
}

function RetentionFacts({ retention }: { retention: AuditRetention }) {
  const deletesStoredMonths =
    retention.oldestStoredMonth !== null &&
    retention.oldestRetainedMonth !== null &&
    retention.oldestStoredMonth < retention.oldestRetainedMonth;
  return (
    <DetailList>
      <DetailItem label="Current period">
        {formatRetentionPeriod(retention.months)} (about{" "}
        {retention.retentionDays.toLocaleString("en-US")} days)
      </DetailItem>
      <DetailItem label="Oldest stored month">
        {retention.oldestStoredMonth ? (
          <>
            {formatMonth(retention.oldestStoredMonth)}
            {deletesStoredMonths && retention.oldestRetainedMonth ? (
              <span className="block text-muted-foreground">
                Months before {formatMonth(retention.oldestRetainedMonth)} are
                deleted at the next deletion run
                {retention.confirmed ? "" : " once the period is confirmed"}.
              </span>
            ) : null}
          </>
        ) : (
          "No entries stored"
        )}
      </DetailItem>
      <DetailItem label="Applies from">
        {retention.effectiveFrom
          ? formatDateTime(retention.effectiveFrom)
          : "Not scheduled until confirmed"}
      </DetailItem>
      <DetailItem label="Last changed">
        {retention.updatedAt ? (
          <>
            {formatDateTime(retention.updatedAt)}
            {retention.previousMonths !== null
              ? ` (from ${formatRetentionPeriod(retention.previousMonths)})`
              : null}
          </>
        ) : (
          "Never"
        )}
      </DetailItem>
      <DetailItem label="Last confirmed">
        {retention.confirmedAt
          ? formatDateTime(retention.confirmedAt)
          : "Never"}
      </DetailItem>
    </DetailList>
  );
}

interface PendingSave {
  months: number;
  reason: string;
  /** When the save was asked for; only an older backend's estimate uses it. */
  nowMs: number;
}

/** Below this many characters left, the counter is announced. */
const ANNOUNCE_REMAINING = 50;

function reasonCountAnnouncement(count: number): string {
  const remaining = MAX_REASON_LENGTH - count;
  if (remaining > ANNOUNCE_REMAINING) return "";
  const characters = (n: number) =>
    n === 1 ? "1 character" : `${n} characters`;
  return remaining >= 0
    ? `${characters(remaining)} left`
    : `${characters(-remaining)} over the limit`;
}

function AuditRetentionSettings({
  retention,
  onRefresh,
  isRefreshing,
  refreshFailed,
}: {
  retention: AuditRetention;
  onRefresh: () => void;
  isRefreshing: boolean;
  refreshFailed: boolean;
}) {
  const setRetention = useSetAuditRetention();
  const [choice, setChoice] = useState<RetentionChoice>(() =>
    choiceForMonths(retention.months),
  );
  const [customMonths, setCustomMonths] = useState(() =>
    choiceForMonths(retention.months) === "custom"
      ? String(retention.months)
      : "",
  );
  const [reasonInput, setReasonInput] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [pending, setPending] = useState<PendingSave | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);

  // A refused save carries the server's current bounds; validate against those.
  const { minMonths, maxMonths } =
    getAuditRetentionBounds(setRetention.error) ?? retention;
  const monthsResult = validateMonths(
    choice === "custom" ? customMonths : choice,
    minMonths,
    maxMonths,
  );
  const reasonResult = validateReason(reasonInput);
  const reasonCount = reasonLength(reasonInput);
  const showMonthsError =
    monthsResult.error !== null && (submitted || customMonths.trim() !== "");
  const showReasonError =
    reasonResult.error !== null &&
    (submitted || reasonCount > MAX_REASON_LENGTH);

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitted(true);
    if (monthsResult.months === null || reasonResult.reason === null) return;
    setPending({
      months: monthsResult.months,
      reason: reasonResult.reason,
      nowMs: Date.now(),
    });
    setDialogOpen(true);
    // When deletion would start moves with time and with the job's switches:
    // ask the server again so the dialog states its current answer.
    onRefresh();
  };

  const confirmSave = () => {
    if (!pending) return;
    setRetention.mutate(
      { months: pending.months, reason: pending.reason },
      {
        onSuccess: () => {
          setReasonInput("");
          setSubmitted(false);
        },
      },
    );
  };

  return (
    <>
      <RetentionStatusBanner retention={retention} />
      <RetentionFacts retention={retention} />

      <form
        aria-label="Change audit retention"
        className="space-y-5 border-t border-divider pt-5"
        noValidate
        onSubmit={handleSubmit}
      >
        <PeriodField
          choice={choice}
          customMonths={customMonths}
          error={showMonthsError ? monthsResult.error : null}
          maxMonths={maxMonths}
          minMonths={minMonths}
          onChoiceChange={setChoice}
          onCustomMonthsChange={setCustomMonths}
        />

        <ReasonField
          count={reasonCount}
          error={showReasonError ? reasonResult.error : null}
          onChange={setReasonInput}
          value={reasonInput}
        />

        {setRetention.isError ? (
          <Alert variant="destructive">
            <WarningOctagonIcon aria-hidden="true" />
            <AlertTitle>Couldn&apos;t save the retention period</AlertTitle>
            <AlertDescription>
              {getApiErrorMessage(setRetention.error, "Please try again.")}
            </AlertDescription>
          </Alert>
        ) : null}

        <Button
          className="w-full sm:w-auto"
          disabled={setRetention.isPending}
          isPending={setRetention.isPending}
          loadingtext="Saving"
          type="submit"
        >
          Save and confirm
        </Button>
      </form>

      <AlertDialog onOpenChange={setDialogOpen} open={dialogOpen}>
        {pending ? (
          <SaveConfirmation
            copy={describeRetentionSave(
              retention,
              pending.months,
              pending.nowMs,
            )}
            isRefreshing={isRefreshing}
            onConfirm={confirmSave}
            reason={pending.reason}
            refreshFailed={refreshFailed}
          />
        ) : null}
      </AlertDialog>
    </>
  );
}

function PeriodField({
  choice,
  customMonths,
  minMonths,
  maxMonths,
  error,
  onChoiceChange,
  onCustomMonthsChange,
}: {
  choice: RetentionChoice;
  customMonths: string;
  minMonths: number;
  maxMonths: number;
  error: string | null;
  onChoiceChange: (choice: RetentionChoice) => void;
  onCustomMonthsChange: (months: string) => void;
}) {
  const ids = { months: useId(), monthsHint: useId(), monthsError: useId() };
  return (
    <div className="space-y-2">
      <p aria-hidden="true" className="text-sm font-medium text-foreground">
        Keep audit entries for
      </p>
      {/* Five segments don't fit a phone: below sm the same choice is a select. */}
      <div className="sm:hidden" data-testid="retention-choice-select">
        <Select
          onValueChange={(value) => onChoiceChange(value as RetentionChoice)}
          value={choice}
        >
          <SelectTrigger aria-label="Keep audit entries for">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RETENTION_CHOICES.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="hidden sm:block" data-testid="retention-choice-segments">
        <SegmentedControl
          aria-label="Keep audit entries for"
          onValueChange={onChoiceChange}
          options={RETENTION_CHOICES}
          value={choice}
        />
      </div>
      {choice === "custom" ? (
        <div className="space-y-1.5 pt-1">
          <Label htmlFor={ids.months}>Months</Label>
          <Input
            aria-describedby={cn(
              ids.monthsHint,
              error !== null && ids.monthsError,
            )}
            aria-invalid={error !== null || undefined}
            className="w-32"
            id={ids.months}
            inputMode="numeric"
            max={maxMonths}
            min={minMonths}
            onChange={(event) => onCustomMonthsChange(event.target.value)}
            type="number"
            value={customMonths}
          />
          <p className="text-xs text-muted-foreground" id={ids.monthsHint}>
            {minMonths} to {maxMonths} months.
          </p>
        </div>
      ) : null}
      {error !== null ? (
        <p className="text-sm text-destructive" id={ids.monthsError}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

function ReasonField({
  value,
  count,
  error,
  onChange,
}: {
  value: string;
  count: number;
  error: string | null;
  onChange: (value: string) => void;
}) {
  const ids = {
    reason: useId(),
    reasonHint: useId(),
    count: useId(),
    reasonError: useId(),
  };
  return (
    <div className="space-y-1.5">
      <Label htmlFor={ids.reason}>Reason</Label>
      <Textarea
        aria-describedby={cn(
          ids.reasonHint,
          ids.count,
          error !== null && ids.reasonError,
        )}
        aria-invalid={error !== null || undefined}
        aria-required="true"
        id={ids.reason}
        onChange={(event) => onChange(event.target.value)}
        placeholder="For example: customer contract requires 2 years of audit history"
        rows={3}
        value={value}
      />
      <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
        <p className="text-xs text-muted-foreground" id={ids.reasonHint}>
          Kept in the platform&apos;s internal audit trail, never shown to
          customers.
        </p>
        <p
          className={cn(
            "text-xs tabular-nums",
            count > MAX_REASON_LENGTH
              ? "text-destructive"
              : "text-muted-foreground",
          )}
          id={ids.count}
        >
          {count}/{MAX_REASON_LENGTH} characters
        </p>
      </div>
      <p aria-live="polite" className="sr-only">
        {reasonCountAnnouncement(count)}
      </p>
      {error !== null ? (
        <p className="text-sm text-destructive" id={ids.reasonError}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

function SaveConfirmation({
  copy,
  reason,
  isRefreshing,
  refreshFailed,
  onConfirm,
}: {
  copy: RetentionSaveCopy;
  reason: string;
  isRefreshing: boolean;
  refreshFailed: boolean;
  onConfirm: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const critical = copy.destructive
    ? [...copy.consequences, copy.caveat]
    : copy.consequences;
  return (
    <AlertDialogContent
      className="sm:max-w-lg"
      onOpenAutoFocus={(event) => {
        // A deleting confirmation never starts on its destructive action.
        if (!copy.destructive) return;
        event.preventDefault();
        cancelRef.current?.focus();
      }}
    >
      <AlertDialogHeader>
        <AlertDialogTitle>{copy.title}</AlertDialogTitle>
        <AlertDialogDescription>{copy.description}</AlertDialogDescription>
      </AlertDialogHeader>

      {isRefreshing ? (
        <p className="text-sm text-muted-foreground" role="status">
          Checking when deletion would start…
        </p>
      ) : (
        <>
          {critical.length > 0 ? (
            <Alert variant="destructive">
              <WarningOctagonIcon aria-hidden="true" />
              <AlertDescription>
                <ul className="list-disc space-y-1 pl-4">
                  {critical.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              </AlertDescription>
            </Alert>
          ) : null}

          {copy.destructive ? null : (
            <Alert variant="info">
              <InfoIcon aria-hidden="true" />
              <AlertDescription>{copy.caveat}</AlertDescription>
            </Alert>
          )}

          {refreshFailed ? (
            <p className="text-sm text-muted-foreground">
              Couldn&apos;t check the latest schedule; these dates are from when
              the page loaded.
            </p>
          ) : null}
        </>
      )}

      <p className="text-sm wrap-break-word text-muted-foreground">
        <span className="font-medium text-foreground">Reason:</span> {reason}
      </p>

      <AlertDialogFooter>
        <AlertDialogCancel ref={cancelRef}>
          Keep current setting
        </AlertDialogCancel>
        <AlertDialogAction
          disabled={isRefreshing}
          onClick={onConfirm}
          variant={copy.destructive ? "destructive" : "default"}
        >
          {copy.actionLabel}
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  );
}
