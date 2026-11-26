// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type {
  CredentialCategory,
  CredentialProvider,
  CredentialRecord,
  CredentialType,
  CredentialTypeDefinition,
} from "@/types/ssl";
import type { CredentialReferenceType } from "@/types/cert-manager";
import { getGcpAuthModeSecretTemplate } from "@/lib/credential-config-schemas/gcp-shared";

export interface ProviderConfig {
  label: string;
  logo: string;
  gradient: string;
  docs: string;
}

export interface IntegrationProviderOption {
  value: CredentialProvider;
  label: string;
  credentialType: CredentialType;
  description?: string;
  docs: string;
  logo: string;
}

export interface IntegrationTypeOption {
  credentialType: CredentialType;
  label: string;
  description?: string;
  category: CredentialCategory;
  provider?: CredentialProvider;
}

export interface SelectedIntegrationType {
  provider: CredentialProvider;
  credentialType: CredentialType;
  label: string;
  category: CredentialCategory;
  description?: string;
}

export interface CredentialReferenceProviderDefinition {
  providerKey: CredentialProvider;
  apiValue: string;
  label: string;
  type: CredentialReferenceType;
  docs: string;
  logo: string;
  description: string;
  targetType?: string;
  secretPayloadTemplate?: string;
}

export interface ProviderPresentation {
  label: string;
  logo?: string;
  providerKey?: CredentialProvider;
}

const AWS_ACCESS_KEYS_SECRET_TEMPLATE = JSON.stringify(
  {
    accessKeyId: "ACCESS_KEY_ID",
    secretAccessKey: "SECRET_ACCESS_KEY",
  },
  null,
  2,
);

const AZURE_CLIENT_SECRET_TEMPLATE = JSON.stringify(
  {
    clientId: "AZURE_CLIENT_ID",
    clientSecret: "AZURE_CLIENT_SECRET",
  },
  null,
  2,
);

const KUBERNETES_SA_TOKEN_SECRET_TEMPLATE = JSON.stringify(
  {
    apiServer: "https://YOUR_CLUSTER_API_SERVER",
    caCertBase64: "BASE64_ENCODED_CA_PEM",
    bearerToken: "K8S_BEARER_TOKEN",
  },
  null,
  2,
);

const CREDENTIAL_DOCS = {
  akamaiCps: "https://techdocs.akamai.com/cps/docs/welcome-cert-prov-system",
  awsAcm:
    "https://docs.aws.amazon.com/acm/latest/userguide/import-certificate-prerequisites.html",
  awsApiGateway:
    "https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-custom-domains.html",
  awsCloudFront:
    "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html",
  awsLoadBalancer:
    "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-update-certificates.html",
  awsRoute53:
    "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/access-control-managing-permissions.html",
  azureAppGateway:
    "https://learn.microsoft.com/en-us/azure/application-gateway/key-vault-certs",
  azureAksRole:
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/containers#azure-kubernetes-service-cluster-user-role",
  azureDns:
    "https://learn.microsoft.com/en-us/azure/dns/dns-protect-zones-recordsets",
  azureFrontDoor:
    "https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/how-to-configure-https-custom-domain",
  azureKeyVault:
    "https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios",
  cloudflareApiToken:
    "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
  cloudflareCustomCertificates:
    "https://developers.cloudflare.com/ssl/edge-certificates/custom-certificates/uploading/",
  f5ClientSsl:
    "https://clouddocs.f5.com/api/icontrol-rest/APIRef_tm_ltm_profile_client-ssl.html",
  gcpCertificateManager: "https://cloud.google.com/certificate-manager/docs",
  gcpCertificateMaps: "https://cloud.google.com/certificate-manager/docs/maps",
  gcpLoadBalancingCertificates:
    "https://cloud.google.com/load-balancing/docs/ssl-certificates/google-managed-certs",
  godaddy: "https://developer.godaddy.com/getstarted",
  hostinger: "https://developers.hostinger.com/",
  kubernetesRbac:
    "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
  namecom: "https://docs.name.com/docs/api-reference-overview",
  namecheap:
    "https://www.namecheap.com/support/knowledgebase/article.aspx/9539/29/how-to-start-using-namecheap-api/",
  // Docs page, not the API base URL - this is rendered as a "documentation" link.
  certpingDns:
    "https://github.com/certping-labs/certping/blob/main/docs/integrations.md#dns-providers",
} as const;

const CREDENTIAL_TYPE_LABELS: Record<string, string> = {
  aws_acm: "AWS Certificate Manager",
  aws_route53: "AWS Route 53",
  aws_access_key: "AWS Access Key",
  azure_key_vault: "Azure Key Vault",
  azure_service_principal: "Azure Service Principal",
  azure_dns: "Azure DNS",
  cloudflare_api_token: "Cloudflare API Token",
  cloudflare_global_key: "Cloudflare Global Key",
  cloudflare_api: "Cloudflare API",
  godaddy_dns: "GoDaddy DNS",
  godaddy_api: "GoDaddy API",
  namedotcom_dns: "Name.com DNS",
  namecom_dns: "Name.com DNS",
  hostinger_dns: "Hostinger DNS",
};

const PROVIDER_VALUE_LABELS: Record<string, string> = {
  akamai_cps: "Akamai CPS",
  aws_acm: "AWS Certificate Manager",
  aws_alb: "AWS Application Load Balancer",
  aws_api_gw_http: "AWS API Gateway HTTP/WebSocket",
  aws_api_gw_rest: "AWS API Gateway REST",
  aws_nlb: "AWS Network Load Balancer",
  aws_organization: "AWS (account or organization)",
  azure_afd: "Azure Front Door",
  azure_app_gw: "Azure Application Gateway",
  azure_app_gw_containers: "Azure App Gateway for Containers",
  gcp_cert_manager: "GCP Certificate Manager",
  gcp_alb: "GCP Load Balancer (ALB)",
  gcp_proxy_nlb: "GCP Proxy NLB",
  gcp_api_gw: "GCP API Gateway",
  gcp_cloud_cdn: "GCP Cloud CDN",
  aws_route53: "AWS Route 53",
  azure_dns: "Azure DNS",
  azure_kv: "Azure Key Vault",
  cloudflare_edge: "Cloudflare Edge",
  cloudflare: "Cloudflare",
  digicert: "DigiCert",
  f5_bigip: "F5 BIG-IP",
  globalsign: "GlobalSign",
  godaddy: "GoDaddy",
  lets_encrypt: "Let's Encrypt",
  kubernetes_secrets: "Kubernetes Secrets",
  namecom: "Name.com",
  hostinger: "Hostinger",
};

const PROVIDER_TYPE_ALIASES: Record<string, CredentialProvider> = {
  akamai_cps: "akamai",
  aws_acm: "aws",
  aws_alb: "aws",
  aws_api_gw_http: "aws",
  aws_api_gw_rest: "aws",
  aws_nlb: "aws",
  aws_route53: "aws",
  aws_access_key: "aws",
  aws_route53_dns_credentials: "aws",
  azure_key_vault: "azure",
  azure_service_principal: "azure",
  azure_dns: "azure",
  azure_afd: "azure",
  azure_app_gw: "azure",
  azure_app_gw_containers: "azure",
  gcp_cert_manager: "gcp",
  gcp_alb: "gcp",
  gcp_proxy_nlb: "gcp",
  gcp_api_gw: "gcp",
  gcp_cloud_cdn: "gcp",
  cloudflare_api_token: "cloudflare",
  cloudflare_edge: "cloudflare",
  cloudflare_api: "cloudflare",
  cloudflare_global_key: "cloudflare",
  powerdns: "certping",
  certping_dns: "certping",
  godaddy_dns: "godaddy",
  godaddy_dns_credentials: "godaddy",
  godaddy_api: "godaddy",
  namedotcom_dns: "namecom",
  namecom_dns: "namecom",
  namecom_dns_credentials: "namecom",
  namedotcom: "namecom",
  namecom: "namecom",
  hostinger_dns: "hostinger",
  hostinger_dns_credentials: "hostinger",
  hostinger: "hostinger",
  namecheap_dns: "namecheap",
  namecheap_dns_credentials: "namecheap",
  namecheap: "namecheap",
  f5_bigip: "f5",
  kubernetes_secrets: "kubernetes",
};

const PROVIDER_TYPE_PRIORITY: Record<CredentialProvider, readonly string[]> = {
  aws: ["aws_acm", "aws_route53", "aws_access_key"],
  azure: ["azure_key_vault", "azure_service_principal", "azure_dns"],
  gcp: ["gcp_cert_manager"],
  cloudflare: [
    "cloudflare_api_token",
    "cloudflare_global_key",
    "cloudflare_api",
  ],
  godaddy: ["godaddy_dns", "godaddy_dns_credentials", "godaddy_api"],
  namecom: ["namedotcom_dns", "namecom_dns", "namecom_dns_credentials"],
  hostinger: ["hostinger_dns", "hostinger_dns_credentials"],
  namecheap: ["namecheap_dns", "namecheap_dns_credentials"],
  certping: ["powerdns", "certping_dns"],
  kubernetes: ["kubernetes_secrets"],
  akamai: ["akamai_cps"],
  f5: ["f5_bigip"],
};

export const CREDENTIAL_PROVIDER_CONFIG: Record<
  CredentialProvider,
  ProviderConfig
> = {
  aws: {
    label: "AWS",
    logo: "/assets/aws.svg",
    gradient: "from-orange-100 to-orange-200",
    docs: CREDENTIAL_DOCS.awsAcm,
  },
  azure: {
    label: "Azure",
    logo: "/assets/azure.svg",
    gradient: "from-blue-100 to-blue-200",
    docs: CREDENTIAL_DOCS.azureKeyVault,
  },
  gcp: {
    label: "GCP",
    logo: "/assets/gcp.svg",
    gradient: "from-sky-100 to-sky-200",
    docs: CREDENTIAL_DOCS.gcpCertificateManager,
  },
  cloudflare: {
    label: "Cloudflare",
    logo: "/assets/cloudflare.svg",
    gradient: "from-amber-100 to-amber-200",
    docs: CREDENTIAL_DOCS.cloudflareApiToken,
  },
  godaddy: {
    label: "GoDaddy",
    logo: "/assets/godaddy.svg",
    gradient: "from-slate-100 to-slate-200",
    docs: CREDENTIAL_DOCS.godaddy,
  },
  namecom: {
    label: "Name.com",
    logo: "/assets/namecom.svg",
    gradient: "from-zinc-100 to-zinc-200",
    docs: CREDENTIAL_DOCS.namecom,
  },
  hostinger: {
    label: "Hostinger",
    logo: "/assets/hostinger.svg",
    gradient: "from-violet-100 to-violet-200",
    docs: CREDENTIAL_DOCS.hostinger,
  },
  namecheap: {
    label: "Namecheap",
    logo: "/assets/namecheap.svg",
    gradient: "from-violet-100 to-violet-200",
    docs: CREDENTIAL_DOCS.namecheap,
  },
  certping: {
    label: "CertPing DNS",
    logo: "/assets/certping.svg",
    gradient: "from-teal-100 to-teal-200",
    docs: CREDENTIAL_DOCS.certpingDns,
  },
  kubernetes: {
    label: "Kubernetes",
    logo: "/assets/kubernetes.svg",
    gradient: "from-blue-100 to-blue-200",
    docs: CREDENTIAL_DOCS.kubernetesRbac,
  },
  akamai: {
    label: "Akamai",
    logo: "/assets/akamai.svg",
    gradient: "from-slate-100 to-slate-200",
    docs: CREDENTIAL_DOCS.akamaiCps,
  },
  f5: {
    label: "F5",
    logo: "/assets/f5.svg",
    gradient: "from-indigo-100 to-indigo-200",
    docs: CREDENTIAL_DOCS.f5ClientSsl,
  },
};

export const CREDENTIAL_REFERENCE_PROVIDER_OPTIONS: CredentialReferenceProviderDefinition[] =
  [
    {
      providerKey: "aws",
      apiValue: "AWS_ROUTE53",
      label: "AWS Route 53",
      type: "DNS",
      docs: CREDENTIAL_DOCS.awsRoute53,
      logo: CREDENTIAL_PROVIDER_CONFIG.aws.logo,
      description:
        "Reference a Route 53 DNS credential stored in your secret manager.",
      secretPayloadTemplate:
        '{"awsRegion":"us-east-1","hostedZoneId":"Z1234567890","accessKeyId":"<access-key-id>","secretAccessKey":"<secret-access-key>"}',
    },
    {
      providerKey: "cloudflare",
      apiValue: "CLOUDFLARE",
      label: "Cloudflare DNS",
      type: "DNS",
      docs: CREDENTIAL_DOCS.cloudflareApiToken,
      logo: CREDENTIAL_PROVIDER_CONFIG.cloudflare.logo,
      description:
        "Reference a Cloudflare DNS credential stored in your secret manager.",
      secretPayloadTemplate:
        '{"apiToken":"<cloudflare-api-token>","zoneId":"<optional-zone-id>"}',
    },
    {
      providerKey: "godaddy",
      apiValue: "GODADDY",
      label: "GoDaddy DNS",
      type: "DNS",
      docs: CREDENTIAL_DOCS.godaddy,
      logo: CREDENTIAL_PROVIDER_CONFIG.godaddy.logo,
      description:
        "Reference a GoDaddy DNS credential stored in your secret manager.",
      secretPayloadTemplate:
        '{"apiKey":"<godaddy-api-key>","apiSecret":"<godaddy-api-secret>"}',
    },
    {
      providerKey: "namecom",
      apiValue: "NAMEDOTCOM",
      label: "Name.com DNS",
      type: "DNS",
      docs: CREDENTIAL_DOCS.namecom,
      logo: CREDENTIAL_PROVIDER_CONFIG.namecom.logo,
      description:
        "Reference a Name.com DNS credential stored in your secret manager.",
      secretPayloadTemplate:
        '{"username":"<namecom-username>","apiToken":"<namecom-api-token>"}',
    },
    {
      providerKey: "hostinger",
      apiValue: "HOSTINGER",
      label: "Hostinger DNS",
      type: "DNS",
      docs: CREDENTIAL_DOCS.hostinger,
      logo: CREDENTIAL_PROVIDER_CONFIG.hostinger.logo,
      description:
        "Reference a Hostinger DNS credential stored in your secret manager.",
      secretPayloadTemplate: '{"apiToken":"<hostinger-api-token>"}',
    },
    {
      providerKey: "namecheap",
      apiValue: "NAMECHEAP",
      label: "Namecheap DNS",
      type: "DNS",
      docs: CREDENTIAL_DOCS.namecheap,
      logo: CREDENTIAL_PROVIDER_CONFIG.namecheap.logo,
      description:
        "Reference a Namecheap DNS credential stored in your secret manager.",
      secretPayloadTemplate:
        '{"apiUser":"<namecheap-api-user>","username":"<namecheap-username>","apiKey":"<namecheap-api-key>"}',
    },
    {
      providerKey: "certping",
      apiValue: "CERTPING",
      label: "CertPing DNS",
      type: "DNS",
      docs: CREDENTIAL_DOCS.certpingDns,
      logo: CREDENTIAL_PROVIDER_CONFIG.certping.logo,
      description:
        "Use a CertPing DNS API token (cpk_live_…) against domains on CertPing nameservers.",
      secretPayloadTemplate: '{"apiKey":"cpk_live_…"}',
    },
    {
      providerKey: "azure",
      apiValue: "AZURE_KV",
      label: "Azure Key Vault",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.azureKeyVault,
      logo: CREDENTIAL_PROVIDER_CONFIG.azure.logo,
      description: "Reference a deployment credential for Azure Key Vault.",
      targetType: "AZURE_KV",
      secretPayloadTemplate: AZURE_CLIENT_SECRET_TEMPLATE,
    },
    {
      providerKey: "aws",
      apiValue: "AWS_ACM",
      label: "AWS Certificate Manager",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.awsAcm,
      logo: CREDENTIAL_PROVIDER_CONFIG.aws.logo,
      description:
        "Reference a deployment credential for AWS Certificate Manager.",
      targetType: "AWS_ACM",
      secretPayloadTemplate: AWS_ACCESS_KEYS_SECRET_TEMPLATE,
    },
    {
      providerKey: "azure",
      apiValue: "AZURE_APP_GW",
      label: "Azure Application Gateway",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.azureAppGateway,
      logo: CREDENTIAL_PROVIDER_CONFIG.azure.logo,
      description:
        "Reference a deployment credential for Azure Application Gateway TLS updates.",
      targetType: "AZURE_APP_GW",
      secretPayloadTemplate: AZURE_CLIENT_SECRET_TEMPLATE,
    },
    {
      providerKey: "azure",
      apiValue: "AZURE_AFD",
      label: "Azure Front Door",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.azureFrontDoor,
      logo: CREDENTIAL_PROVIDER_CONFIG.azure.logo,
      description:
        "Reference a deployment credential for Azure Front Door custom-domain TLS updates.",
      targetType: "AZURE_AFD",
      secretPayloadTemplate: AZURE_CLIENT_SECRET_TEMPLATE,
    },
    {
      providerKey: "aws",
      apiValue: "AWS_ALB",
      label: "AWS Application Load Balancer",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.awsLoadBalancer,
      logo: CREDENTIAL_PROVIDER_CONFIG.aws.logo,
      description:
        "Reference a deployment credential for AWS ALB listener certificate updates.",
      targetType: "AWS_ALB",
      secretPayloadTemplate: AWS_ACCESS_KEYS_SECRET_TEMPLATE,
    },
    {
      providerKey: "aws",
      apiValue: "AWS_NLB",
      label: "AWS Network Load Balancer",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.awsLoadBalancer,
      logo: CREDENTIAL_PROVIDER_CONFIG.aws.logo,
      description:
        "Reference a deployment credential for AWS NLB listener certificate updates.",
      targetType: "AWS_NLB",
      secretPayloadTemplate: AWS_ACCESS_KEYS_SECRET_TEMPLATE,
    },
    {
      providerKey: "aws",
      apiValue: "AWS_API_GW_REST",
      label: "AWS API Gateway REST",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.awsApiGateway,
      logo: CREDENTIAL_PROVIDER_CONFIG.aws.logo,
      description:
        "Reference a deployment credential for AWS API Gateway REST custom domain TLS updates.",
      targetType: "AWS_API_GW_REST",
      secretPayloadTemplate: AWS_ACCESS_KEYS_SECRET_TEMPLATE,
    },
    {
      providerKey: "aws",
      apiValue: "AWS_API_GW_HTTP",
      label: "AWS API Gateway HTTP/WebSocket",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.awsApiGateway,
      logo: CREDENTIAL_PROVIDER_CONFIG.aws.logo,
      description:
        "Reference a deployment credential for AWS API Gateway HTTP/WebSocket custom domains.",
      targetType: "AWS_API_GW_HTTP",
      secretPayloadTemplate: AWS_ACCESS_KEYS_SECRET_TEMPLATE,
    },
    {
      providerKey: "aws",
      apiValue: "AWS_CLOUDFRONT",
      label: "AWS CloudFront",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.awsCloudFront,
      logo: CREDENTIAL_PROVIDER_CONFIG.aws.logo,
      description:
        "Reference a deployment credential for AWS CloudFront distribution TLS updates.",
      targetType: "AWS_CLOUDFRONT",
      secretPayloadTemplate: AWS_ACCESS_KEYS_SECRET_TEMPLATE,
    },
    {
      providerKey: "cloudflare",
      apiValue: "CLOUDFLARE_EDGE",
      label: "Cloudflare Edge",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.cloudflareCustomCertificates,
      logo: CREDENTIAL_PROVIDER_CONFIG.cloudflare.logo,
      description:
        "Reference a deployment credential for Cloudflare Edge custom SSL updates.",
      targetType: "CLOUDFLARE_EDGE",
      secretPayloadTemplate: '{"apiToken":"<cloudflare-api-token>"}',
    },
    {
      providerKey: "kubernetes",
      apiValue: "KUBERNETES_SECRETS",
      label: "Kubernetes Secrets",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.kubernetesRbac,
      logo: CREDENTIAL_PROVIDER_CONFIG.kubernetes.logo,
      description:
        "Reference a deployment credential for Kubernetes TLS secrets.",
      targetType: "KUBERNETES_SECRETS",
      secretPayloadTemplate: KUBERNETES_SA_TOKEN_SECRET_TEMPLATE,
    },
    {
      providerKey: "akamai",
      apiValue: "AKAMAI_CPS",
      label: "Akamai CPS",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.akamaiCps,
      logo: CREDENTIAL_PROVIDER_CONFIG.akamai.logo,
      description:
        "Reference a deployment credential for Akamai CPS third-party enrollment updates.",
      targetType: "AKAMAI_CPS",
      secretPayloadTemplate:
        '{"clientToken":"akab-...","accessToken":"akab-...","clientSecret":"<client-secret>"}',
    },
    {
      providerKey: "f5",
      apiValue: "F5_BIGIP",
      label: "F5 BIG-IP",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.f5ClientSsl,
      logo: CREDENTIAL_PROVIDER_CONFIG.f5.logo,
      description:
        "Reference a deployment credential for F5 BIG-IP client SSL profile updates.",
      targetType: "F5_BIGIP",
      secretPayloadTemplate: '{"username":"admin","password":"<password>"}',
    },
    {
      providerKey: "gcp",
      apiValue: "GCP_CERT_MANAGER",
      label: "GCP Certificate Manager",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.gcpCertificateMaps,
      logo: CREDENTIAL_PROVIDER_CONFIG.gcp.logo,
      description:
        "Reference a deployment credential for GCP Certificate Manager (certificate maps and entries).",
      targetType: "GCP_CERT_MANAGER",
      secretPayloadTemplate: getGcpAuthModeSecretTemplate(
        "SERVICE_ACCOUNT_KEY",
      ),
    },
    {
      providerKey: "gcp",
      apiValue: "GCP_ALB",
      label: "GCP Load Balancer (ALB)",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.gcpLoadBalancingCertificates,
      logo: CREDENTIAL_PROVIDER_CONFIG.gcp.logo,
      description:
        "Reference a deployment credential for GCP target HTTPS proxy updates (ALB).",
      targetType: "GCP_ALB",
      secretPayloadTemplate: getGcpAuthModeSecretTemplate(
        "SERVICE_ACCOUNT_KEY",
      ),
    },
    {
      providerKey: "gcp",
      apiValue: "GCP_PROXY_NLB",
      label: "GCP Proxy NLB",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.gcpLoadBalancingCertificates,
      logo: CREDENTIAL_PROVIDER_CONFIG.gcp.logo,
      description:
        "Reference a deployment credential for GCP target SSL proxy updates (proxy NLB).",
      targetType: "GCP_PROXY_NLB",
      secretPayloadTemplate: getGcpAuthModeSecretTemplate(
        "SERVICE_ACCOUNT_KEY",
      ),
    },
    {
      providerKey: "gcp",
      apiValue: "GCP_API_GW",
      label: "GCP API Gateway",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.gcpLoadBalancingCertificates,
      logo: CREDENTIAL_PROVIDER_CONFIG.gcp.logo,
      description:
        "Reference a deployment credential for GCP API Gateway TLS deployments.",
      targetType: "GCP_API_GW",
      secretPayloadTemplate: getGcpAuthModeSecretTemplate(
        "SERVICE_ACCOUNT_KEY",
      ),
    },
    {
      providerKey: "gcp",
      apiValue: "GCP_CLOUD_CDN",
      label: "GCP Cloud CDN",
      type: "DEPLOYMENT",
      docs: CREDENTIAL_DOCS.gcpLoadBalancingCertificates,
      logo: CREDENTIAL_PROVIDER_CONFIG.gcp.logo,
      description:
        "Reference a deployment credential for GCP Cloud CDN TLS updates via the proxy flow.",
      targetType: "GCP_CLOUD_CDN",
      secretPayloadTemplate: getGcpAuthModeSecretTemplate(
        "SERVICE_ACCOUNT_KEY",
      ),
    },
  ];

function normalizeKey(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  return normalized || undefined;
}

export function formatProviderLabel(value: string | undefined): string {
  const normalized = normalizeKey(value);
  if (!normalized) {
    return "Unknown";
  }

  const directMatch = PROVIDER_VALUE_LABELS[normalized];
  if (directMatch) {
    return directMatch;
  }

  const optionMatch = CREDENTIAL_REFERENCE_PROVIDER_OPTIONS.find(
    (option) => option.apiValue.toLowerCase() === normalized,
  );
  if (optionMatch) {
    return optionMatch.label;
  }

  return normalized
    .split("_")
    .filter(Boolean)
    .map((segment) => {
      const upper = segment.toUpperCase();
      if (upper === "AWS" || upper === "DNS" || upper === "KV") {
        return upper;
      }
      return segment[0].toUpperCase() + segment.slice(1);
    })
    .join(" ");
}

export function getCredentialReferenceProviderOptions(
  type: CredentialReferenceType,
): CredentialReferenceProviderDefinition[] {
  // Intentionally hide these providers in UI:
  // GCP API Gateway and GCP Cloud CDN are usually fronted by a GCP load balancer,
  // and they currently use the same credential/config flow as GCP ALB. Keeping all
  // three visible is redundant and causes operator confusion during credential setup.
  const HIDDEN_PROVIDER_API_VALUES = new Set(["GCP_API_GW", "GCP_CLOUD_CDN"]);

  return CREDENTIAL_REFERENCE_PROVIDER_OPTIONS.filter(
    (option) =>
      option.type === type && !HIDDEN_PROVIDER_API_VALUES.has(option.apiValue),
  );
}

export function getCredentialTypeLabel(
  credentialType: string | undefined,
): string {
  const normalized = normalizeKey(credentialType);
  if (!normalized) {
    return "Unknown";
  }

  if (normalized in CREDENTIAL_TYPE_LABELS) {
    return CREDENTIAL_TYPE_LABELS[normalized];
  }

  return normalized
    .split("_")
    .filter(Boolean)
    .map((segment) => segment[0].toUpperCase() + segment.slice(1))
    .join(" ");
}

export function tryGetCredentialProviderFromType(
  credentialType: string | undefined,
): CredentialProvider | undefined {
  const normalized = normalizeKey(credentialType);
  if (!normalized) {
    return undefined;
  }

  if (normalized in PROVIDER_TYPE_ALIASES) {
    return PROVIDER_TYPE_ALIASES[normalized];
  }

  if (normalized.startsWith("azure")) {
    return "azure";
  }
  if (normalized.startsWith("cloudflare")) {
    return "cloudflare";
  }
  if (normalized.startsWith("godaddy")) {
    return "godaddy";
  }
  if (normalized.startsWith("namecom") || normalized.startsWith("namedotcom")) {
    return "namecom";
  }
  if (normalized.startsWith("hostinger")) {
    return "hostinger";
  }
  if (normalized.startsWith("aws")) {
    return "aws";
  }
  if (normalized.startsWith("gcp")) {
    return "gcp";
  }

  return undefined;
}

export function getCredentialProviderFromType(
  credentialType: string | undefined,
): CredentialProvider {
  return tryGetCredentialProviderFromType(credentialType) || "aws";
}

export function resolveCredentialProvider(
  record: Pick<
    CredentialRecord,
    "provider" | "providerName" | "credentialType" | "typeName"
  >,
): CredentialProvider {
  const normalizedProvider = normalizeKey(
    record.provider || record.providerName,
  );
  if (normalizedProvider && normalizedProvider in PROVIDER_TYPE_ALIASES) {
    return PROVIDER_TYPE_ALIASES[normalizedProvider];
  }

  if (normalizedProvider && normalizedProvider in CREDENTIAL_PROVIDER_CONFIG) {
    return normalizedProvider as CredentialProvider;
  }

  return (
    tryGetCredentialProviderFromType(
      record.typeName || record.credentialType,
    ) || "aws"
  );
}

export function resolveCredentialProviderFromApiValue(
  value: string | undefined,
): CredentialProvider | undefined {
  const normalized = normalizeKey(value);
  if (!normalized) {
    return undefined;
  }

  const matchedOption = CREDENTIAL_REFERENCE_PROVIDER_OPTIONS.find(
    (option) => option.apiValue.toLowerCase() === normalized,
  );
  return matchedOption?.providerKey;
}

export function getProviderLogoByApiValue(
  value: string | undefined,
): string | undefined {
  const providerKey = resolveCredentialProviderFromApiValue(value);
  return providerKey ? CREDENTIAL_PROVIDER_CONFIG[providerKey].logo : undefined;
}

export function getProviderPresentation(
  value: string | undefined,
  providerKey?: CredentialProvider,
): ProviderPresentation {
  const resolvedProviderKey =
    providerKey || resolveCredentialProviderFromApiValue(value);

  return {
    label: formatProviderLabel(value),
    logo: resolvedProviderKey
      ? CREDENTIAL_PROVIDER_CONFIG[resolvedProviderKey].logo
      : undefined,
    providerKey: resolvedProviderKey,
  };
}

function getCredentialProvider(value: string): CredentialProvider | null {
  const normalized = normalizeKey(value);
  if (!normalized) {
    return null;
  }

  return tryGetCredentialProviderFromType(normalized) || null;
}

function getTypePriority(
  provider: CredentialProvider,
  credentialType: string,
): number {
  const normalized = normalizeKey(credentialType);
  if (!normalized) {
    return Number.MAX_SAFE_INTEGER;
  }

  const priorities = PROVIDER_TYPE_PRIORITY[provider];
  const index = priorities.indexOf(normalized);
  if (index >= 0) {
    return index;
  }

  return priorities.length + 1;
}

export function toIntegrationOptions(
  credentialTypes: CredentialTypeDefinition[],
): IntegrationProviderOption[] {
  if (credentialTypes.length === 0) {
    return [];
  }

  const options = new Map<CredentialProvider, IntegrationProviderOption>();

  credentialTypes.forEach((credentialTypeDefinition) => {
    const provider =
      getCredentialProvider(credentialTypeDefinition.providerName || "") ||
      getCredentialProvider(credentialTypeDefinition.typeName);
    if (!provider) {
      return;
    }

    const providerConfig = CREDENTIAL_PROVIDER_CONFIG[provider];
    const typeLabel = getCredentialTypeLabel(credentialTypeDefinition.typeName);

    const nextOption: IntegrationProviderOption = {
      value: provider,
      docs: providerConfig.docs,
      logo: providerConfig.logo,
      credentialType: credentialTypeDefinition.typeName,
      label:
        typeLabel !== "Unknown"
          ? typeLabel
          : credentialTypeDefinition.providerDisplayName ||
            credentialTypeDefinition.providerName ||
            providerConfig.label,
      description: credentialTypeDefinition.description,
    };

    const existingOption = options.get(provider);
    if (!existingOption) {
      options.set(provider, nextOption);
      return;
    }

    const existingPriority = getTypePriority(
      provider,
      existingOption.credentialType,
    );
    const nextPriority = getTypePriority(provider, nextOption.credentialType);
    if (nextPriority < existingPriority) {
      options.set(provider, nextOption);
    }
  });

  return Array.from(options.values());
}

export function toIntegrationTypeOptions(
  credentialTypes: CredentialTypeDefinition[],
): IntegrationTypeOption[] {
  const seen = new Set<string>();
  const options: IntegrationTypeOption[] = [];

  credentialTypes.forEach((credentialTypeDefinition) => {
    const normalizedType = credentialTypeDefinition.typeName
      .trim()
      .toLowerCase();
    if (!normalizedType || seen.has(normalizedType)) {
      return;
    }

    seen.add(normalizedType);
    const provider =
      tryGetCredentialProviderFromType(credentialTypeDefinition.providerName) ||
      tryGetCredentialProviderFromType(normalizedType);

    options.push({
      credentialType: normalizedType,
      label: getCredentialTypeLabel(normalizedType),
      description: credentialTypeDefinition.description,
      category: credentialTypeDefinition.category,
      provider,
    });
  });

  return options.sort((left, right) =>
    left.label.localeCompare(right.label, undefined, { sensitivity: "base" }),
  );
}
