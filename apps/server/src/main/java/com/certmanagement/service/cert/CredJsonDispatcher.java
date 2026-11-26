// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.certmanagement.dto.credconfig.credjson.ca.DigiCertCaCredJson;
import com.certmanagement.dto.credconfig.credjson.deployment.AkamaiCpsDeploymentCredJson;
import com.certmanagement.dto.credconfig.credjson.deployment.AwsDeploymentCredJson;
import com.certmanagement.dto.credconfig.credjson.deployment.AzureDeploymentCredJson;
import com.certmanagement.dto.credconfig.credjson.deployment.AzureKvDiscoveryCredJson;
import com.certmanagement.dto.credconfig.credjson.deployment.CloudflareEdgeDeploymentCredJson;
import com.certmanagement.dto.credconfig.credjson.deployment.F5BigIpDeploymentCredJson;
import com.certmanagement.dto.credconfig.credjson.deployment.GcpCertificateManagerDeploymentCredJson;
import com.certmanagement.dto.credconfig.credjson.deployment.KubernetesDeploymentCredJson;
import com.certmanagement.dto.credconfig.credjson.dns.AwsRoute53DnsCredJson;
import com.certmanagement.dto.credconfig.credjson.dns.CertPingDnsCredJson;
import com.certmanagement.dto.credconfig.credjson.dns.CertPingDnsKeyConfig;
import com.certmanagement.dto.credconfig.credjson.dns.CloudflareDnsCredJson;
import com.certmanagement.dto.credconfig.credjson.dns.GoDaddyDnsCredJson;
import com.certmanagement.dto.credconfig.credjson.dns.HostingerDnsCredJson;
import com.certmanagement.dto.credconfig.credjson.dns.NamecheapDnsConfigJson;
import com.certmanagement.dto.credconfig.credjson.dns.NamecheapDnsCredJson;
import com.certmanagement.dto.credconfig.credjson.dns.NameDotComDnsCredJson;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.CredentialRejectedException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates a user-supplied {@code credJson} against the typed DTO for the provider, then
 * returns the exact bytes to write to the agent KV — so the agent's reader (which uses the
 * mirror DTO on its side) parses the same shape it always has.
 *
 * <p>For Cloudflare DNS (and only Cloudflare DNS), the agent reads a bare API token string,
 * not JSON. The payload's {@link CredJsonPayload#serializesToBareString()} hook handles that.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CredJsonDispatcher {

    /** AWS deployment-target providers — all share AwsDeploymentCredJson. */
    private static final Set<String> AWS_DEPLOYMENT_PROVIDERS = Set.of(
            "AWS_ACM", "AWS_ALB", "AWS_NLB", "AWS_API_GW_REST", "AWS_API_GW_HTTP", "AWS_CLOUDFRONT");

    /** Azure deployment-target providers — all share AzureDeploymentCredJson. */
    private static final Set<String> AZURE_DEPLOYMENT_PROVIDERS = Set.of(
            "AZURE_APP_GW", "AZURE_APP_GW_CONTAINERS", "AZURE_AFD");

    /** GCP deployment-target providers — all share GcpCertificateManagerDeploymentCredJson. */
    private static final Set<String> GCP_DEPLOYMENT_PROVIDERS = Set.of(
            "GCP_CERT_MANAGER", "GCP_ALB", "GCP_PROXY_NLB", "GCP_API_GW", "GCP_CLOUD_CDN");

    private static final Map<String, Class<? extends CredJsonPayload>> DNS_PROVIDER_TO_DTO = Map.of(
            "AWS_ROUTE53", AwsRoute53DnsCredJson.class,
            "CLOUDFLARE",  CloudflareDnsCredJson.class,
            "GODADDY",     GoDaddyDnsCredJson.class,
            "NAMECHEAP",   NamecheapDnsCredJson.class,
            "NAMEDOTCOM",  NameDotComDnsCredJson.class,
            "HOSTINGER",   HostingerDnsCredJson.class,
            "CERTPING",    CertPingDnsCredJson.class);

    private static final Map<String, Class<? extends CredJsonPayload>> DEPLOYMENT_PROVIDER_TO_DTO = Map.of(
            "CLOUDFLARE_EDGE",    CloudflareEdgeDeploymentCredJson.class,
            "KUBERNETES_SECRETS", KubernetesDeploymentCredJson.class,
            "AKAMAI_CPS",         AkamaiCpsDeploymentCredJson.class,
            "F5_BIGIP",           F5BigIpDeploymentCredJson.class,
            "AZURE_KV",           AzureKvDiscoveryCredJson.class);

    private static final Map<String, Class<? extends CredJsonPayload>> CA_PROVIDER_TO_DTO = Map.of(
            "DIGICERT", DigiCertCaCredJson.class);

    /** What the CertPing DNS portal shows of a key: {@code cpk_live_} and its first 8 characters, never more. */
    private static final Pattern CERTPING_KEY_PREFIX = Pattern.compile("cpk_live_[0-9A-Za-z]{8}");

    private final ObjectMapper objectMapper;

    /**
     * Validates that {@code credJson} matches the provider's typed shape and returns the
     * JSON string to persist in KV. Unknown fields are stripped (per DTO {@code @JsonIgnoreProperties}).
     *
     * @throws BadRequestException if provider is unknown, has no credJson DTO mirror, or the payload is malformed
     */
    public String serializeForKv(String provider, String credentialType, JsonNode credJson) {
        if (credJson == null || credJson.isNull() || credJson.isMissingNode()) {
            throw new BadRequestException("credJson is required");
        }
        Class<? extends CredJsonPayload> dtoClass = resolveDtoClass(provider, credentialType);
        return serializeTypedPayload(provider, credJson, dtoClass);
    }

    /** Validates and serializes a CertPing DNS key's non-secret details for the credential's config. */
    public String serializeCertPingKeyConfig(JsonNode configJson) {
        if (configJson == null || configJson.isNull() || configJson.isMissingNode()) {
            throw new BadRequestException("The CertPing DNS key's details are required.");
        }
        return serializeTypedPayload("CERTPING", configJson, CertPingDnsKeyConfig.class);
    }

    /** Serializes only the non-secret Namecheap fields kept in a credential's configuration. */
    public String serializeNamecheapAccountConfig(JsonNode configJson) {
        if (configJson == null || configJson.isNull() || configJson.isMissingNode()) {
            throw new BadRequestException("Namecheap account details are required.");
        }
        return serializeTypedPayload("NAMECHEAP", configJson, NamecheapDnsConfigJson.class);
    }

    private String serializeTypedPayload(String provider, JsonNode source,
            Class<? extends CredJsonPayload> dtoClass) {
        CredJsonPayload payload;
        try {
            payload = objectMapper.treeToValue(source, dtoClass);
        } catch (Exception ex) {
            throw new CredentialRejectedException(CredentialRejectedException.DETAILS_INVALID,
                    "The credential details provided for " + provider + " are not valid.", ex);
        }
        validatePayload(provider, payload);
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception ex) {
            // Round-tripping a typed instance through writeValueAsString should never fail.
            throw new IllegalStateException("Failed to re-serialize cred payload for provider " + provider, ex);
        }
    }

    private void validatePayload(String provider, CredJsonPayload payload) {
        if (payload instanceof NamecheapDnsCredJson namecheap) {
            requireNonBlank("Namecheap API user is required.", namecheap.getApiUser());
            requireNonBlank("Namecheap username is required.", namecheap.getUsername());
            requireNonBlank("Namecheap API key is required.", namecheap.getApiKey());
        } else if (payload instanceof NamecheapDnsConfigJson namecheapConfig) {
            requireNonBlank("Namecheap API user is required.", namecheapConfig.getApiUser());
            requireNonBlank("Namecheap username is required.", namecheapConfig.getUsername());
        } else if (payload instanceof DigiCertCaCredJson digiCert) {
            requireNonBlank("DigiCert API key is required.", digiCert.getApiKey());
        } else if (payload instanceof CertPingDnsCredJson certPing) {
            requireNonBlank("CertPing DNS API key is required.", certPing.getApiKey());
        } else if (payload instanceof CertPingDnsKeyConfig key) {
            validateCertPingKey(key);
        } else if (payload instanceof KubernetesDeploymentCredJson kubernetes) {
            validateKubernetesClusterCa(kubernetes);
        }
    }

    /**
     * A service account token credential (API server and token, used out of cluster) needs the cluster CA:
     * the agent always verifies the API server and has no skip-TLS option.
     */
    private void validateKubernetesClusterCa(KubernetesDeploymentCredJson credential) {
        boolean serviceAccountToken = !isBlank(credential.getApiServer()) || !isBlank(credential.getBearerToken())
                || !isBlank(credential.getServiceAccountToken());
        if (!serviceAccountToken) {
            return;
        }
        byte[] ca;
        if (!isBlank(credential.getCaCertPem())) {
            ca = credential.getCaCertPem().getBytes(StandardCharsets.UTF_8);
        } else if (!isBlank(credential.getCaCertBase64())) {
            try {
                ca = Base64.getMimeDecoder().decode(credential.getCaCertBase64().trim());
            } catch (IllegalArgumentException ex) {
                throw new CredentialRejectedException(CredentialRejectedException.DETAILS_INVALID,
                        "The cluster CA certificate (caCertBase64) is not valid base64.");
            }
        } else {
            throw new CredentialRejectedException(CredentialRejectedException.DETAILS_INVALID,
                    "The cluster CA certificate is required (caCertPem or caCertBase64). "
                            + "CertPing always verifies the Kubernetes API server certificate.");
        }
        try {
            if (CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(ca)).isEmpty()) {
                throw new IllegalArgumentException("no certificate");
            }
        } catch (Exception ex) {
            throw new CredentialRejectedException(CredentialRejectedException.DETAILS_INVALID,
                    "The cluster CA certificate must be a PEM certificate or the base64 "
                            + "certificate-authority-data from your kubeconfig.");
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private void validateCertPingKey(CertPingDnsKeyConfig key) {
        if (key.getTokenId() == null || key.getTokenId() < 1) {
            throw new CredentialRejectedException(CredentialRejectedException.DETAILS_INVALID,
                    "The CertPing DNS key's token id is required.");
        }
        if (key.getTokenPrefix() == null || !CERTPING_KEY_PREFIX.matcher(key.getTokenPrefix()).matches()) {
            throw new CredentialRejectedException(CredentialRejectedException.DETAILS_INVALID,
                    "The CertPing DNS key's prefix must be cpk_live_ and the 8 characters the portal shows.");
        }
        if (key.getExpiresAt() == null) {
            throw new CredentialRejectedException(CredentialRejectedException.DETAILS_INVALID,
                    "The CertPing DNS key's expiry is required.");
        }
    }

    private void requireNonBlank(String message, String value) {
        if (value == null || value.isBlank()) {
            throw new CredentialRejectedException(CredentialRejectedException.DETAILS_INVALID, message);
        }
    }

    /**
     * True when the dispatcher knows how to handle credJson for the given (provider, type).
     * Used by controller/service to decide whether to gate-error or proceed.
     */
    public boolean supports(String provider, String credentialType) {
        try {
            resolveDtoClass(provider, credentialType);
            return true;
        } catch (BadRequestException ex) {
            return false;
        }
    }

    private Class<? extends CredJsonPayload> resolveDtoClass(String provider, String credentialType) {
        if (provider == null || provider.isBlank()) {
            throw new BadRequestException("provider is required to validate credJson");
        }
        String normalizedProvider = provider.toUpperCase();
        String normalizedType = credentialType == null ? "" : credentialType.toUpperCase();

        if ("DNS".equals(normalizedType)) {
            Class<? extends CredJsonPayload> dto = DNS_PROVIDER_TO_DTO.get(normalizedProvider);
            if (dto == null) {
                throw new BadRequestException("No credJson DTO mirror for DNS provider: " + provider);
            }
            return dto;
        }

        if ("CA".equals(normalizedType)) {
            Class<? extends CredJsonPayload> dto = CA_PROVIDER_TO_DTO.get(normalizedProvider);
            if (dto == null) {
                throw new BadRequestException("No credJson DTO mirror for CA provider: " + provider);
            }
            return dto;
        }

        // AWS_ORGANIZATION (discovery) uses the same optional bootstrap keys as AWS deployment.
        if ("AWS_ORGANIZATION".equals(normalizedProvider)) {
            return AwsDeploymentCredJson.class;
        }

        // DEPLOYMENT: provider-family lookups first, then provider-specific.
        if (AWS_DEPLOYMENT_PROVIDERS.contains(normalizedProvider)) {
            return AwsDeploymentCredJson.class;
        }
        if (AZURE_DEPLOYMENT_PROVIDERS.contains(normalizedProvider)) {
            return AzureDeploymentCredJson.class;
        }
        if (GCP_DEPLOYMENT_PROVIDERS.contains(normalizedProvider)) {
            return GcpCertificateManagerDeploymentCredJson.class;
        }
        Class<? extends CredJsonPayload> dto = DEPLOYMENT_PROVIDER_TO_DTO.get(normalizedProvider);
        if (dto == null) {
            throw new BadRequestException("No credJson DTO mirror for deployment provider: " + provider);
        }
        return dto;
    }
}
