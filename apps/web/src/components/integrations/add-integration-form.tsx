// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import { ReactElement, SVGProps, useEffect, useMemo, useState } from "react";
import {
  DotsThreeIcon,
  PencilSimpleIcon,
  TrashIcon,
} from "@phosphor-icons/react";
import { useForm } from "react-hook-form";

import {
  MicrosoftTeams,
  PagerDuty,
  ServiceNow,
  Slack,
} from "@/components/icons/logos";
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
import { BetaBadge } from "@/components/common/beta-badge";
import { isBetaIntegration } from "@/lib/integration-maturity";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useCreateIntegration,
  useDeleteIntegration,
  useListIntegrations,
  useUpdateIntegration,
} from "@/hooks/integrations";
import { useAuth } from "@/hooks/use-auth";
import { canManageIntegrations } from "@/lib/authz";
import { formatDateTime } from "@/lib/utils";
import type {
  CreateIntegrationPayload,
  Integration,
  IntegrationProvider,
  UpdateIntegrationPayload,
} from "@/types/integrations";

type ProviderConfig = {
  provider: IntegrationProvider;
  name: string;
  useCase: string;
  icon: (props: SVGProps<SVGSVGElement>) => ReactElement;
};

type DialogMode = "create" | "update";

type IntegrationDraft = {
  webhookUrl: string;
  routingKey: string;
  instanceUrl: string;
  clientId: string;
  clientSecret: string;
  oauthScope: string;
};

function RequiredMark() {
  return (
    <span className="ml-1 text-destructive" aria-hidden="true">
      *
    </span>
  );
}

type ActiveDialog = {
  config: ProviderConfig;
  integration?: Integration;
  mode: DialogMode;
};

const PROVIDERS: ProviderConfig[] = [
  {
    provider: "SLACK",
    name: "Slack",
    useCase: "Team notifications for certificate events and incidents.",
    icon: Slack,
  },
  {
    provider: "TEAMS",
    name: "Microsoft Teams",
    useCase: "Channel updates for expiry alerts, deployments, and incidents.",
    icon: MicrosoftTeams,
  },
  {
    provider: "PAGERDUTY",
    name: "PagerDuty",
    useCase: "On-call escalation for critical certificate and platform issues.",
    icon: PagerDuty,
  },
  {
    provider: "SERVICENOW_ITSM",
    name: "ServiceNow ITSM",
    useCase: "ITSM ticketing for certificate and operational incidents.",
    icon: ServiceNow,
  },
];

const EMPTY_DRAFT: IntegrationDraft = {
  webhookUrl: "",
  routingKey: "",
  instanceUrl: "",
  clientId: "",
  clientSecret: "",
  oauthScope: "",
};

const PROVIDER_COPY: Record<
  IntegrationProvider,
  { title: string; description: string; submit: string }
> = {
  SLACK: {
    title: "Connect Slack",
    description: "Add the incoming webhook URL for the Slack channel.",
    submit: "Connect Slack",
  },
  TEAMS: {
    title: "Connect Microsoft Teams",
    description: "Add the Teams workflow or incoming webhook URL.",
    submit: "Connect Teams",
  },
  PAGERDUTY: {
    title: "Connect PagerDuty",
    description: "Add an Events API v2 routing key for incident creation.",
    submit: "Connect PagerDuty",
  },
  SERVICENOW_ITSM: {
    title: "Connect ServiceNow ITSM",
    description: "Add your ServiceNow instance and OAuth credentials.",
    submit: "Connect ServiceNow",
  },
};

const trimOptional = (value: string): string | undefined => {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const buildCreatePayload = (
  provider: IntegrationProvider,
  draft: IntegrationDraft,
): CreateIntegrationPayload => {
  if (provider === "SLACK" || provider === "TEAMS") {
    return {
      provider,
      webhookUrl: draft.webhookUrl.trim(),
    };
  }

  if (provider === "PAGERDUTY") {
    return {
      provider,
      routingKey: draft.routingKey.trim(),
    };
  }

  return {
    provider,
    instanceUrl: draft.instanceUrl.trim(),
    clientId: draft.clientId.trim(),
    clientSecret: draft.clientSecret.trim(),
    oauthScope: trimOptional(draft.oauthScope),
  };
};

const buildUpdatePayload = (
  provider: IntegrationProvider,
  draft: IntegrationDraft,
): UpdateIntegrationPayload => {
  if (provider === "SLACK" || provider === "TEAMS") {
    return {
      webhookUrl: draft.webhookUrl.trim(),
    };
  }

  if (provider === "PAGERDUTY") {
    return {
      routingKey: draft.routingKey.trim(),
    };
  }

  return {
    instanceUrl: draft.instanceUrl.trim(),
    clientId: draft.clientId.trim(),
    clientSecret: draft.clientSecret.trim(),
    oauthScope: trimOptional(draft.oauthScope),
  };
};

const getRequiredFieldsFilled = (
  provider: IntegrationProvider,
  draft: IntegrationDraft,
): boolean => {
  if (provider === "SLACK" || provider === "TEAMS") {
    return draft.webhookUrl.trim().length > 0;
  }

  if (provider === "PAGERDUTY") {
    return draft.routingKey.trim().length > 0;
  }

  return (
    draft.instanceUrl.trim().length > 0 &&
    draft.clientId.trim().length > 0 &&
    draft.clientSecret.trim().length > 0
  );
};

export function IntegrationsManager() {
  const { user } = useAuth();
  const [activeDialog, setActiveDialog] = useState<ActiveDialog | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{
    config: ProviderConfig;
    integration: Integration;
  } | null>(null);
  const integrationsQuery = useListIntegrations();
  const deleteIntegration = useDeleteIntegration();
  const canManage = canManageIntegrations(user);

  const integrationsByProvider = useMemo(() => {
    const integrations = integrationsQuery.data ?? [];
    return new Map(integrations.map((item) => [item.provider, item]));
  }, [integrationsQuery.data]);

  const handleDelete = async () => {
    if (!deleteTarget) {
      return;
    }

    await deleteIntegration.mutateAsync(deleteTarget.integration.id);
    setDeleteTarget(null);
  };

  if (integrationsQuery.isLoading) {
    return <IntegrationSkeleton />;
  }

  return (
    <>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {PROVIDERS.map((config) => {
          const integration = integrationsByProvider.get(config.provider);
          const isConnected =
            integration?.status === "ACTIVE" && integration.deletedAt == null;

          return (
            <IntegrationCard
              canManage={canManage}
              config={config}
              integration={integration}
              isConnected={isConnected}
              key={config.provider}
              onConnect={() =>
                setActiveDialog({
                  config,
                  mode: "create",
                })
              }
              onDelete={() => {
                if (integration) {
                  setDeleteTarget({ config, integration });
                }
              }}
              onUpdate={() => {
                if (integration) {
                  setActiveDialog({
                    config,
                    integration,
                    mode: "update",
                  });
                }
              }}
            />
          );
        })}
      </div>

      <IntegrationDialog
        activeDialog={activeDialog}
        onOpenChange={(open) => {
          if (!open) {
            setActiveDialog(null);
          }
        }}
      />

      <AlertDialog
        open={deleteTarget != null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleteTarget(null);
          }
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete integration</AlertDialogTitle>
            <AlertDialogDescription>
              This will remove the active {deleteTarget?.config.name}{" "}
              integration for your organization. You can reconnect it later.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-[hsl(var(--destructive-700))]"
              disabled={deleteIntegration.isPending}
              onClick={(event) => {
                event.preventDefault();
                void handleDelete();
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function IntegrationCard({
  canManage,
  config,
  integration,
  isConnected,
  onConnect,
  onDelete,
  onUpdate,
}: {
  canManage: boolean;
  config: ProviderConfig;
  integration: Integration | undefined;
  isConnected: boolean;
  onConnect: () => void;
  onDelete: () => void;
  onUpdate: () => void;
}) {
  const Icon = config.icon;

  return (
    <Card className="flex flex-col">
      <CardHeader className="space-y-4 pb-1">
        <div className="flex items-start justify-between gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-border/70 bg-background shadow-(--shadow-xs)">
            <Icon className="h-7 w-7" />
          </div>
          {isConnected && canManage ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  aria-label={`${config.name} actions`}
                  size="iconSm"
                  variant="iconSm"
                >
                  <DotsThreeIcon className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={onUpdate}>
                  <PencilSimpleIcon className="h-4 w-4" />
                  Update
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  className="text-destructive focus:text-destructive"
                  onClick={onDelete}
                >
                  <TrashIcon className="h-4 w-4" />
                  Delete
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : null}
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <CardTitle className="text-base">{config.name}</CardTitle>
              {isBetaIntegration("NOTIFICATION", config.provider) ? (
                <BetaBadge />
              ) : null}
            </div>
            {isConnected && (
              <div className="text-xs text-muted-foreground">
                {integration?.updatedAt
                  ? formatDateTime(integration.updatedAt)
                  : "-"}
              </div>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-4">
        <p className="text-sm text-muted-foreground">{config.useCase}</p>
        {!isConnected && canManage ? (
          <Button
            variant="outline"
            className="mt-auto w-full"
            onClick={onConnect}
          >
            Connect {config.name}
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}

function IntegrationDialog({
  activeDialog,
  onOpenChange,
}: {
  activeDialog: ActiveDialog | null;
  onOpenChange: (open: boolean) => void;
}) {
  const form = useForm<IntegrationDraft>({
    defaultValues: EMPTY_DRAFT,
    mode: "onBlur",
    reValidateMode: "onChange",
  });
  const createIntegration = useCreateIntegration();
  const updateIntegration = useUpdateIntegration(
    activeDialog?.integration?.id ?? "",
  );
  const config = activeDialog?.config;
  const mode = activeDialog?.mode ?? "create";
  const draft = form.watch();

  useEffect(() => {
    if (activeDialog) {
      form.reset(EMPTY_DRAFT);
    }
  }, [activeDialog, form]);

  const resetAndClose = () => {
    form.reset(EMPTY_DRAFT);
    onOpenChange(false);
  };

  const handleSubmit = form.handleSubmit(async (values) => {
    if (!config || !getRequiredFieldsFilled(config.provider, draft)) {
      return;
    }

    if (mode === "create") {
      await createIntegration.mutateAsync(
        buildCreatePayload(config.provider, values),
      );
    } else if (activeDialog?.integration) {
      await updateIntegration.mutateAsync(
        buildUpdatePayload(config.provider, values),
      );
    }

    resetAndClose();
  });

  const isPending = createIntegration.isPending || updateIntegration.isPending;
  const isSubmitDisabled =
    !config || !getRequiredFieldsFilled(config.provider, draft) || isPending;
  const copy = config ? PROVIDER_COPY[config.provider] : null;
  const title =
    mode === "update" && config ? `Update ${config.name}` : copy?.title;

  return (
    <Dialog
      open={activeDialog != null}
      onOpenChange={(open) => {
        if (!open) {
          resetAndClose();
          return;
        }
        onOpenChange(open);
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {mode === "update"
              ? "Replace the stored credentials for this integration."
              : copy?.description}
          </DialogDescription>
        </DialogHeader>
        {config ? (
          <Form {...form}>
            <form className="space-y-5" onSubmit={handleSubmit}>
              <ProviderFields form={form} provider={config.provider} />
              <DialogFooter>
                <Button
                  disabled={isPending}
                  onClick={() => resetAndClose()}
                  type="button"
                  variant="outline"
                >
                  Cancel
                </Button>
                <Button
                  disabled={isSubmitDisabled}
                  isPending={isPending}
                  type="submit"
                >
                  {mode === "update" ? "Update integration" : copy?.submit}
                </Button>
              </DialogFooter>
            </form>
          </Form>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function ProviderFields({
  form,
  provider,
}: {
  form: ReturnType<typeof useForm<IntegrationDraft>>;
  provider: IntegrationProvider;
}) {
  if (provider === "SLACK" || provider === "TEAMS") {
    return (
      <FormField
        control={form.control}
        name="webhookUrl"
        rules={{ required: "Webhook URL is required" }}
        render={({ field }) => (
          <FormItem>
            <FormLabel>
              Webhook URL
              <RequiredMark />
            </FormLabel>
            <FormControl>
              <Input
                {...field}
                autoComplete="off"
                placeholder="https://hooks.example.com/..."
                required
                type="url"
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
    );
  }

  if (provider === "PAGERDUTY") {
    return (
      <FormField
        control={form.control}
        name="routingKey"
        rules={{ required: "Routing key is required" }}
        render={({ field }) => (
          <FormItem>
            <FormLabel>
              Routing key
              <RequiredMark />
            </FormLabel>
            <FormControl>
              <Input
                {...field}
                autoComplete="off"
                placeholder="Events API v2 routing key"
                required
                type="password"
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
    );
  }

  return (
    <div className="space-y-4">
      <FormField
        control={form.control}
        name="instanceUrl"
        rules={{ required: "Instance URL is required" }}
        render={({ field }) => (
          <FormItem>
            <FormLabel>
              Instance URL
              <RequiredMark />
            </FormLabel>
            <FormControl>
              <Input
                {...field}
                autoComplete="off"
                placeholder="https://example.service-now.com"
                required
                type="url"
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="clientId"
        rules={{ required: "Client ID is required" }}
        render={({ field }) => (
          <FormItem>
            <FormLabel>
              Client ID
              <RequiredMark />
            </FormLabel>
            <FormControl>
              <Input
                {...field}
                autoComplete="off"
                placeholder="certping-support-client"
                required
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="clientSecret"
        rules={{ required: "Client secret is required" }}
        render={({ field }) => (
          <FormItem>
            <FormLabel>
              Client secret
              <RequiredMark />
            </FormLabel>
            <FormControl>
              <Input
                {...field}
                autoComplete="off"
                placeholder="OAuth client secret"
                required
                type="password"
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="oauthScope"
        render={({ field }) => (
          <FormItem>
            <FormLabel>OAuth scope</FormLabel>
            <FormControl>
              <Input {...field} autoComplete="off" placeholder="Optional" />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
    </div>
  );
}

function IntegrationSkeleton() {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {PROVIDERS.map((provider) => (
        <Card className="min-h-[260px]" key={provider.provider}>
          <CardHeader className="space-y-4">
            <Skeleton className="h-12 w-12 rounded-lg" />
            <div className="space-y-2">
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-4/5" />
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-10 w-full" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
