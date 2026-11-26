// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import type { ReactNode } from "react";
import { WarningIcon, ShieldWarningIcon } from "@phosphor-icons/react";
import type { FieldValues, UseFormReturn } from "react-hook-form";

import { StringListFormField } from "@/components/common/string-list-form-field";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { isEnterpriseAppMode } from "@/lib/auth-ui-mode";
import {
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { AwsAcmAuthMode } from "@/lib/credential-config-schemas/aws-acm";
import type { AwsApiGwAuthMode } from "@/lib/credential-config-schemas/aws-api-gateway";
import type { AwsCloudFrontAuthMode } from "@/lib/credential-config-schemas/aws-cloudfront";
import type { AwsLoadBalancerAuthMode } from "@/lib/credential-config-schemas/aws-load-balancer";
import type { AzureAgcAuthMode } from "@/lib/credential-config-schemas/azure-agc";
import type { AzureAfdAuthMode } from "@/lib/credential-config-schemas/azure-afd";
import type { AzureAppGwAuthMode } from "@/lib/credential-config-schemas/azure-app-gw";
import type { AzureKvAuthMode } from "@/lib/credential-config-schemas/azure-kv";
import type { GcpAuthMode } from "@/lib/credential-config-schemas/gcp-shared";
import type { KubernetesAuthMethod } from "@/lib/credential-config-schemas/kubernetes-secrets";
import type { CredentialReferenceType } from "@/types/cert-manager";

function TextInput<TFieldValues extends FieldValues>({
  form,
  name,
  label,
  placeholder,
  type = "text",
  description,
}: {
  form: UseFormReturn<TFieldValues>;
  name: string;
  label: string;
  placeholder?: string;
  type?: "text" | "password";
  description?: string;
}) {
  return (
    <FormField
      control={form.control}
      name={name as never}
      render={({ field }) => (
        <FormItem>
          <FormLabel>{label}</FormLabel>
          <FormControl>
            <Input
              className="h-10"
              placeholder={placeholder}
              type={type}
              autoComplete={type === "password" ? "new-password" : "off"}
              data-1p-ignore="true"
              data-lpignore="true"
              {...field}
            />
          </FormControl>
          {description ? (
            <p className="text-xs text-muted-foreground">{description}</p>
          ) : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function TextareaInput<TFieldValues extends FieldValues>({
  form,
  name,
  label,
  placeholder,
  description,
}: {
  form: UseFormReturn<TFieldValues>;
  name: string;
  label: string;
  placeholder?: string;
  description?: string;
}) {
  return (
    <FormField
      control={form.control}
      name={name as never}
      render={({ field }) => (
        <FormItem>
          <FormLabel>{label}</FormLabel>
          <FormControl>
            <Textarea
              className="min-h-28 font-mono text-xs"
              placeholder={placeholder}
              {...field}
            />
          </FormControl>
          {description ? (
            <p className="text-xs text-muted-foreground">{description}</p>
          ) : null}
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

export function ManagedCredentialFields<TFieldValues extends FieldValues>({
  form,
  type,
  providerApiValue,
  kubernetesAuthMethod,
  awsAcmAuthMode,
  awsElbAuthMode,
  awsApiGwAuthMode,
  awsCloudFrontAuthMode,
  azureKvAuthMode,
  azureAppGwAuthMode,
  azureAgcAzureAuthMode,
  azureAfdAuthMode,
  gcpAuthMode,
  mode,
  usesManagedCredentials = true,
}: {
  form: UseFormReturn<TFieldValues>;
  type: CredentialReferenceType;
  providerApiValue?: string | null;
  kubernetesAuthMethod?: KubernetesAuthMethod | null;
  awsAcmAuthMode?: AwsAcmAuthMode | null;
  awsElbAuthMode?: AwsLoadBalancerAuthMode | null;
  awsApiGwAuthMode?: AwsApiGwAuthMode | null;
  awsCloudFrontAuthMode?: AwsCloudFrontAuthMode | null;
  azureKvAuthMode?: AzureKvAuthMode | null;
  azureAppGwAuthMode?: AzureAppGwAuthMode | null;
  azureAgcAzureAuthMode?: AzureAgcAuthMode | null;
  azureAfdAuthMode?: AzureAfdAuthMode | null;
  gcpAuthMode?: GcpAuthMode | null;
  mode: "create" | "edit";
  usesManagedCredentials?: boolean;
}) {
  const provider = (providerApiValue || "").trim().toUpperCase();
  const isEdit = mode === "edit";
  const usesAwsStaticKeys =
    (provider === "AWS_ACM" && awsAcmAuthMode === "STATIC_KEYS") ||
    ((provider === "AWS_ALB" || provider === "AWS_NLB") &&
      awsElbAuthMode === "STATIC_KEYS") ||
    ((provider === "AWS_API_GW_REST" || provider === "AWS_API_GW_HTTP") &&
      awsApiGwAuthMode === "STATIC_KEYS") ||
    (provider === "AWS_CLOUDFRONT" && awsCloudFrontAuthMode === "STATIC_KEYS");

  let fields: ReactNode = null;

  if (type === "DNS") {
    switch (provider) {
      case "AWS_ROUTE53":
        fields = (
          <div className="grid gap-4 md:grid-cols-2">
            <TextInput
              form={form}
              name="secretDnsAwsAccessKeyId"
              label="AWS access key ID"
            />
            <TextInput
              form={form}
              name="secretDnsAwsSecretAccessKey"
              label="AWS secret access key"
              type="password"
            />
          </div>
        );
        break;
      case "CLOUDFLARE":
        fields = (
          <div className="grid gap-4">
            <TextInput
              form={form}
              name="secretDnsCloudflareApiToken"
              label="Cloudflare API token"
              type="password"
              description="Needs Zone, DNS, Edit and Zone, Zone, Read, or set the zone ID below."
            />
            <TextInput
              form={form}
              name="secretDnsCloudflareZoneId"
              label="Zone ID (optional)"
              description="From the zone's Overview page. Lets a token with DNS Edit only work."
            />
          </div>
        );
        break;
      // Token only - the agent knows the CertPing DNS API base URL. Asking a user
      // to type that hostname just adds a way to get it wrong.
      case "CERTPING":
        fields = (
          <div className="grid gap-4">
            <TextInput
              form={form}
              name="secretDnsCertPingApiKey"
              label="CertPing DNS API token"
              type="password"
              description="Opaque cpk_live_… token for domains on CertPing nameservers."
            />
          </div>
        );
        break;
      case "GODADDY":
        fields = (
          <div className="grid gap-4 md:grid-cols-2">
            <TextInput
              form={form}
              name="secretDnsGodaddyApiKey"
              label="GoDaddy API key"
            />
            <TextInput
              form={form}
              name="secretDnsGodaddyApiSecret"
              label="GoDaddy API secret"
              type="password"
            />
          </div>
        );
        break;
      case "NAMEDOTCOM":
        fields = (
          <div className="grid gap-4 md:grid-cols-2">
            <TextInput
              form={form}
              name="secretDnsNamecomUsername"
              label="Name.com username"
            />
            <TextInput
              form={form}
              name="secretDnsNamecomApiToken"
              label="Name.com API token"
              type="password"
            />
          </div>
        );
        break;
      case "HOSTINGER":
        fields = (
          <TextInput
            form={form}
            name="secretDnsHostingerApiToken"
            label="Hostinger API token"
            type="password"
          />
        );
        break;
      case "NAMECHEAP": {
        const outboundIp =
          process.env.NEXT_PUBLIC_NAMECHEAP_OUTBOUND_IP || null;
        const showOutboundIp = Boolean(outboundIp) && !isEnterpriseAppMode();
        fields = (
          <div className="flex flex-col gap-4">
            <div className="grid gap-4 md:grid-cols-2">
              <TextInput
                form={form}
                name="secretDnsNamecheapApiUser"
                label="Namecheap API user"
                description="Usually the same as your Namecheap username."
              />
              <TextInput
                form={form}
                name="secretDnsNamecheapUserName"
                label="Namecheap username"
              />
              {usesManagedCredentials ? (
                <TextInput
                  form={form}
                  name="secretDnsNamecheapApiToken"
                  label="Namecheap API key"
                  type="password"
                  description="From Profile, Tools, API Access in your Namecheap account."
                />
              ) : null}
            </div>
            {!usesManagedCredentials ? (
              <p className="text-xs text-muted-foreground">
                The secret in your vault must be JSON with apiUser, username and
                apiKey. The agent reads all three from it.
              </p>
            ) : null}
            <Alert variant="warning">
              <WarningIcon aria-hidden />
              <AlertTitle>Non-incremental DNS record updates</AlertTitle>
              <AlertDescription className="text-xs leading-relaxed">
                The Namecheap API replaces all host records on each update - any
                records not included in the request will be removed. CertPing
                retrieves the full record set before making changes and
                resubmits all entries alongside the new records. We strongly
                recommend exporting a backup of your DNS records when using this
                integration.
              </AlertDescription>
            </Alert>
            <Alert variant="info">
              <ShieldWarningIcon aria-hidden />
              <AlertTitle>IP whitelisting required</AlertTitle>
              <AlertDescription className="text-xs leading-relaxed">
                Namecheap only accepts API calls from allow-listed IP addresses.
                Add{" "}
                {showOutboundIp ? (
                  <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs font-semibold">
                    {outboundIp}
                  </code>
                ) : (
                  <span className="font-medium">
                    the public IP for where the CertPing agent is running
                  </span>
                )}{" "}
                in your{" "}
                <span className="font-medium">
                  Namecheap dashboard, Profile, Tools, API Access
                </span>{" "}
                to allow CertPing to manage DNS records on your behalf.
                {showOutboundIp ? null : (
                  <>
                    {" "}
                    The agent sends that IP to Namecheap from its
                    NAMECHEAP_CLIENT_IP setting.
                  </>
                )}
              </AlertDescription>
            </Alert>
          </div>
        );
        break;
      }
      default:
        break;
    }
  } else {
    switch (provider) {
      case "AWS_ACM":
      case "AWS_ALB":
      case "AWS_NLB":
      case "AWS_API_GW_REST":
      case "AWS_API_GW_HTTP":
      case "AWS_CLOUDFRONT":
        fields = usesAwsStaticKeys ? (
          <div className="grid gap-4 md:grid-cols-2">
            <TextInput
              form={form}
              name="secretAwsAccessKeyId"
              label="AWS access key ID"
            />
            <TextInput
              form={form}
              name="secretAwsSecretAccessKey"
              label="AWS secret access key"
              type="password"
            />
          </div>
        ) : (
          <Alert>
            <AlertTitle>No stored secret needed</AlertTitle>
            <AlertDescription>
              This auth mode uses workload or instance identity, so CertPing
              does not need to store a credential secret for it.
            </AlertDescription>
          </Alert>
        );
        break;
      case "AZURE_KV":
        fields =
          azureKvAuthMode === "SERVICE_PRINCIPAL" ? (
            <div className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <TextInput
                  form={form}
                  name="secretAzureClientId"
                  label="Client ID"
                />
                <TextInput
                  form={form}
                  name="secretAzureClientSecret"
                  label="Client secret"
                  type="password"
                />
              </div>
              {isEdit ? (
                <p className="text-xs text-muted-foreground">
                  Leave both fields blank to keep the current stored secret.
                </p>
              ) : null}
            </div>
          ) : (
            <Alert>
              <AlertTitle>No stored secret needed</AlertTitle>
              <AlertDescription>
                This auth mode can rely on workload identity, so no credential
                secret needs to be stored here.
              </AlertDescription>
            </Alert>
          );
        break;
      case "AZURE_APP_GW":
        fields =
          azureAppGwAuthMode === "SERVICE_PRINCIPAL" ? (
            <TextInput
              form={form}
              name="secretAzureClientSecret"
              label="Client secret"
              type="password"
              description="The client ID comes from the provider configuration above."
            />
          ) : (
            <Alert>
              <AlertTitle>No stored secret needed</AlertTitle>
              <AlertDescription>
                This auth mode does not require a stored client secret.
              </AlertDescription>
            </Alert>
          );
        break;
      case "AZURE_APP_GW_CONTAINERS":
        fields =
          azureAgcAzureAuthMode === "SERVICE_PRINCIPAL" ? (
            <TextInput
              form={form}
              name="secretAzureClientSecret"
              label="Client secret"
              type="password"
              description="The client ID comes from the provider configuration above."
            />
          ) : (
            <Alert>
              <AlertTitle>No stored secret needed</AlertTitle>
              <AlertDescription>
                This auth mode does not require a stored client secret.
              </AlertDescription>
            </Alert>
          );
        break;
      case "AZURE_AFD":
        fields =
          azureAfdAuthMode === "SERVICE_PRINCIPAL" ? (
            <TextInput
              form={form}
              name="secretAzureClientSecret"
              label="Client secret"
              type="password"
              description="The client ID comes from the provider configuration above."
            />
          ) : (
            <Alert>
              <AlertTitle>No stored secret needed</AlertTitle>
              <AlertDescription>
                This auth mode does not require a stored client secret.
              </AlertDescription>
            </Alert>
          );
        break;
      case "GCP_CERT_MANAGER":
      case "GCP_ALB":
      case "GCP_PROXY_NLB":
      case "GCP_API_GW":
      case "GCP_CLOUD_CDN":
        fields =
          gcpAuthMode === "SERVICE_ACCOUNT_KEY" ? (
            <TextareaInput
              form={form}
              name="secretGcpServiceAccountKeyJson"
              label="Service account key JSON"
              placeholder='{"type":"service_account","project_id":"my-project"}'
              description={
                isEdit
                  ? "Leave blank to keep the current stored secret."
                  : undefined
              }
            />
          ) : (
            <Alert>
              <AlertTitle>No stored secret needed</AlertTitle>
              <AlertDescription>
                This auth mode can use workload identity instead of a stored
                service account key.
              </AlertDescription>
            </Alert>
          );
        break;
      case "CLOUDFLARE_EDGE":
        fields = (
          <TextInput
            form={form}
            name="secretCloudflareApiToken"
            label="Cloudflare API token"
            type="password"
            description={
              isEdit
                ? "Leave blank to keep the current stored secret."
                : undefined
            }
          />
        );
        break;
      case "KUBERNETES_SECRETS":
        switch (kubernetesAuthMethod || "SA_INCLUSTER") {
          case "SA_TOKEN":
            fields = (
              <div className="space-y-4">
                <p className="text-xs text-muted-foreground">
                  Works with any Kubernetes cluster, including k3s, kubeadm,
                  OpenShift and on-prem. The agent must be able to reach the API
                  server.
                </p>
                <TextInput
                  form={form}
                  name="secretK8sApiServer"
                  label="API server URL"
                  placeholder="https://10.0.0.1:6443"
                  description="The server value from your kubeconfig."
                />
                <TextInput
                  form={form}
                  name="secretK8sBearerToken"
                  label="Service account token"
                  type="password"
                  description="For example: kubectl -n <namespace> create token <service-account>. The service account needs RBAC to manage secrets in the namespaces above."
                />
                <TextareaInput
                  form={form}
                  name="secretK8sCaCertPem"
                  label="Cluster CA certificate"
                  placeholder={
                    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                  }
                  description="Required. Paste the PEM, or the base64 certificate-authority-data value from your kubeconfig. CertPing always verifies the API server certificate, so TLS verification cannot be skipped."
                />
                {isEdit ? (
                  <p className="text-xs text-muted-foreground">
                    Leave all three fields blank to keep the current stored
                    secret.
                  </p>
                ) : null}
              </div>
            );
            break;
          case "AWS":
            fields = (
              <TextInput
                form={form}
                name="secretK8sAwsRegion"
                label="AWS region"
                placeholder="us-east-1"
              />
            );
            break;
          case "AZURE":
            fields = (
              <div className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <TextInput
                    form={form}
                    name="secretK8sAzureTenantId"
                    label="Tenant ID"
                  />
                  <TextInput
                    form={form}
                    name="secretK8sAzureSubscriptionId"
                    label="Subscription ID"
                  />
                </div>
                <TextInput
                  form={form}
                  name="secretK8sAzureResourceGroup"
                  label="Resource group"
                />
                <div className="grid gap-4 md:grid-cols-2">
                  <TextInput
                    form={form}
                    name="secretK8sAzureClientId"
                    label="Client ID"
                  />
                  <TextInput
                    form={form}
                    name="secretK8sAzureClientSecret"
                    label="Client secret"
                    type="password"
                  />
                </div>
              </div>
            );
            break;
          case "GCP":
            fields = (
              <div className="space-y-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <TextInput
                    form={form}
                    name="secretK8sGcpProjectId"
                    label="Project ID"
                  />
                  <TextInput
                    form={form}
                    name="secretK8sGcpLocation"
                    label="Location"
                    placeholder="us-central1"
                  />
                </div>
                <TextareaInput
                  form={form}
                  name="secretK8sGcpServiceAccountKeyJson"
                  label="Service account key JSON (optional)"
                  placeholder='{"type":"service_account","project_id":"my-project"}'
                />
              </div>
            );
            break;
          case "SA_INCLUSTER":
          default:
            fields = (
              <Alert>
                <AlertTitle>No stored secret needed</AlertTitle>
                <AlertDescription>
                  The CertPing agent runs inside this cluster and uses its own
                  pod service account, so there is nothing to paste. Give that
                  service account RBAC to manage secrets in the namespaces
                  above.
                </AlertDescription>
              </Alert>
            );
            break;
        }
        break;
      case "AKAMAI_CPS":
        fields = (
          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <TextInput
                form={form}
                name="secretAkamaiClientToken"
                label="Client token"
              />
              <TextInput
                form={form}
                name="secretAkamaiAccessToken"
                label="Access token"
                type="password"
              />
            </div>
            <TextInput
              form={form}
              name="secretAkamaiClientSecret"
              label="Client secret"
              type="password"
            />
            <div className="grid gap-4 md:grid-cols-2">
              <TextInput
                form={form}
                name="secretAkamaiContractId"
                label="Contract ID"
              />
              <TextInput
                form={form}
                name="secretAkamaiCommonName"
                label="Common name"
              />
            </div>
            <StringListFormField
              form={form}
              name={"secretAkamaiDomains" as never}
              label="Domains"
              placeholder="www.example.com"
              addLabel="Add domain"
            />
            <div className="grid gap-4 md:grid-cols-2">
              <TextInput
                form={form}
                name="secretAkamaiNetwork"
                label="Network"
                placeholder="production"
              />
              <TextInput
                form={form}
                name="secretAkamaiCertType"
                label="Certificate type"
                placeholder="third-party"
              />
            </div>
          </div>
        );
        break;
      case "F5_BIGIP":
        fields = (
          <div className="grid gap-4 md:grid-cols-2">
            <TextInput form={form} name="secretF5Username" label="Username" />
            <TextInput
              form={form}
              name="secretF5Password"
              label="Password"
              type="password"
            />
          </div>
        );
        break;
      default:
        break;
    }
  }

  if (!fields) {
    return null;
  }

  return (
    <div className="space-y-4 rounded-lg border bg-muted/15 p-4">
      <div className="space-y-1">
        <h3 className="text-sm font-semibold">
          {provider === "NAMECHEAP" && !usesManagedCredentials
            ? "Namecheap credential details"
            : "Managed credential secret"}
        </h3>
        {isEdit ? (
          <p className="text-xs text-muted-foreground">
            Leave the fields blank if you only want to update non-secret
            provider settings.
          </p>
        ) : null}
      </div>
      {provider === "KUBERNETES_SECRETS" ? (
        <Alert>
          <AlertTitle>Private cluster access</AlertTitle>
          <AlertDescription>
            CertPing can authenticate with these credentials, but if the
            Kubernetes API is private, the agent must be able to reach it.
            Otherwise it cannot write the TLS secret into the cluster.
          </AlertDescription>
        </Alert>
      ) : null}
      {fields}
    </div>
  );
}
