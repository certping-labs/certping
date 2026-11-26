// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

export const SSL_CERTIFICATE_ALIASES = [
  "ssl",
  "tls",
  "x509",
  "x.509",
  "certificate",
  "certificates",
  "certificate manager",
  "cert manager",
  "certificate lifecycle",
];

export const DNS_CREDENTIAL_ALIASES = [
  "dns target",
  "dns provider",
  "dns credential",
  "issuer credential",
  "hosted zone",
  "zone automation",
  "aws route 53",
  "route 53",
  "route53",
  "cloudflare dns",
  "cloudflare",
  "godaddy",
  "go daddy",
  "name.com",
  "namedotcom",
  "namecom",
];

export const DEPLOYMENT_CREDENTIAL_ALIASES = [
  "deployment target",
  "deployment credential",
  "target credential",
  "delivery target",
  "push certificate",
  "aws acm",
  "acm",
  "aws certificate manager",
  "aws cloudfront",
  "cloudfront",
  "aws alb",
  "alb",
  "application load balancer",
  "aws nlb",
  "nlb",
  "network load balancer",
  "aws api gateway",
  "api gateway",
  "azure key vault",
  "azure kv",
  "akv",
  "key vault",
  "azure front door",
  "front door",
  "afd",
  "azure application gateway",
  "app gateway",
  "app gw",
  "azure app gateway for containers",
  "agc",
  "gcp certificate manager",
  "gcp load balancer",
  "gcp api gateway",
  "gcp cloud cdn",
  "cloud cdn",
  "cloudflare edge",
  "cf edge",
  "kubernetes",
  "k8s",
  "kubernetes secrets",
  "k8s secrets",
  "akamai",
  "akamai cps",
  "f5",
  "f5 big-ip",
  "f5 bigip",
  "big-ip",
  "bigip",
];

/**
 * What an operator types when they mean the Machine Identity module.
 *
 * <p>Almost nobody searches for "machine identity" - they search for the thing
 * in front of them: the MDM they sync from, the enrollment protocol, the CA, or
 * simply "device". Every one of those has to land somewhere.
 */
export const MACHINE_IDENTITY_ALIASES = [
  "machine identity",
  "machine identities",
  "device identity",
  "iot",
  "mdm",
  "endpoint management",
  "intune",
  "microsoft intune",
  "jamf",
  "workspace one",
  "managed device",
  "managed devices",
];

/** Terms that point specifically at device-certificate enrollment. */
export const DEVICE_CERTIFICATE_ALIASES = [
  "scep",
  "device certificate",
  "device certificates",
  "machine certificate",
  "machine certificates",
  "ejbca",
  "smallstep",
  "step ca",
  "private ca",
  "enrollment",
];
