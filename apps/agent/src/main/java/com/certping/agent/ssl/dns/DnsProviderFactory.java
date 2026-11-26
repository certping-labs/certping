// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;

/**
 * Factory that constructs the correct {@link DnsProvider} from a provider name and raw credential.
 *
 * Provider routing:
 *   CLOUDFLARE  → rawCredential is JSON: {apiToken, zoneId?}
 *   AWS_ROUTE53 → rawCredential is JSON: {accessKeyId, secretAccessKey}
 *   GODADDY     → rawCredential is JSON: {apiKey, apiSecret}
 *   NAMEDOTCOM  → rawCredential is JSON: {username, apiToken}
 *   HOSTINGER   → rawCredential is JSON: {apiToken}
 *   NAMECHEAP   → rawCredential is JSON: {apiUser, apiKey, username}; client IP comes from NAMECHEAP_CLIENT_IP
 *   CERTPING    → rawCredential is JSON: {apiKey}; base URL is CERTPING_DNS_API_URL or the
 *                 CertPing token API default. POWERDNS is accepted as a legacy alias.
 */
@Slf4j
@Component
public class DnsProviderFactory {

    /** The DNS providers {@link #create} accepts, without the legacy POWERDNS alias. */
    public static final java.util.List<String> SUPPORTED_PROVIDERS = java.util.List.of(
            "CLOUDFLARE", "AWS_ROUTE53", "GODADDY", "NAMEDOTCOM", "HOSTINGER", "NAMECHEAP", "CERTPING");

    private static final String NAMECHEAP_CLIENT_IP_ENV = "NAMECHEAP_CLIENT_IP";
    private static final String CERTPING_DNS_API_URL_ENV = "CERTPING_DNS_API_URL";

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final Supplier<String> namecheapClientIpSupplier;
    private final Supplier<String> certPingDnsApiUrlSupplier;

    public DnsProviderFactory() {
        this(() -> System.getenv(NAMECHEAP_CLIENT_IP_ENV),
             () -> System.getenv(CERTPING_DNS_API_URL_ENV));
    }

    DnsProviderFactory(Supplier<String> namecheapClientIpSupplier) {
        this(namecheapClientIpSupplier, () -> null);
    }

    DnsProviderFactory(Supplier<String> namecheapClientIpSupplier,
                       Supplier<String> certPingDnsApiUrlSupplier) {
        this.namecheapClientIpSupplier = namecheapClientIpSupplier;
        this.certPingDnsApiUrlSupplier = certPingDnsApiUrlSupplier;
    }

    /**
     * The provider for the credential at {@code dnsCredentialHandle}, read with {@code readSecret}; null without a
     * handle, so a CA service can say a DNS credential is required.
     */
    public DnsProvider createIfConfigured(String dnsProvider, String dnsCredentialHandle,
                                          UnaryOperator<String> readSecret) {
        if (dnsCredentialHandle == null || dnsCredentialHandle.isBlank()) {
            return null;
        }
        return create(dnsProvider, readSecret.apply(dnsCredentialHandle));
    }

    public DnsProvider create(String dnsProvider, String rawCredential) {
        if (dnsProvider == null || dnsProvider.isBlank()) {
            throw new PermanentAgentException("DNS_PROVIDER_UNKNOWN",
                    "dnsProvider is null or blank — cannot route to DNS provider");
        }
        if (rawCredential == null || rawCredential.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    "Raw DNS credential is null or blank for provider: " + dnsProvider);
        }

        return switch (dnsProvider.trim().toUpperCase()) {
            case "CLOUDFLARE" -> {
                Map<String, String> fields = parseJson(rawCredential, dnsProvider);
                String apiToken = requireField(fields, "apiToken", dnsProvider);
                log.debug("Creating CloudflareDnsProvider");
                yield new CloudflareDnsProvider(apiToken, fields.get("zoneId"));
            }
            case "AWS_ROUTE53" -> {
                Map<String, String> fields = parseJson(rawCredential, dnsProvider);
                String accessKeyId = requireField(fields, "accessKeyId", dnsProvider);
                String secretAccessKey = requireField(fields, "secretAccessKey", dnsProvider);
                log.debug("Creating AwsRoute53DnsProvider");
                yield new AwsRoute53DnsProvider(accessKeyId, secretAccessKey);
            }
            case "GODADDY" -> {
                Map<String, String> fields = parseJson(rawCredential, dnsProvider);
                String apiKey = requireField(fields, "apiKey", dnsProvider);
                String apiSecret = requireField(fields, "apiSecret", dnsProvider);
                log.debug("Creating GoDaddyDnsProvider");
                yield new GoDaddyDnsProvider(apiKey, apiSecret);
            }
            case "NAMEDOTCOM" -> {
                Map<String, String> fields = parseJson(rawCredential, dnsProvider);
                String username = requireField(fields, "username", dnsProvider);
                String apiToken = requireField(fields, "apiToken", dnsProvider);
                log.debug("Creating NameDotComDnsProvider");
                yield new NameDotComDnsProvider(username, apiToken);
            }
            case "HOSTINGER" -> {
                Map<String, String> fields = parseJson(rawCredential, dnsProvider);
                String apiToken = requireField(fields, "apiToken", dnsProvider);
                log.debug("Creating HostingerDnsProvider");
                yield new HostingerDnsProvider(apiToken);
            }
            case "NAMECHEAP" -> {
                Map<String, String> fields = parseJson(rawCredential, dnsProvider);
                String apiUser = requireField(fields, "apiUser", dnsProvider);
                String apiKey = requireField(fields, "apiKey", dnsProvider);
                String username = requireField(fields, "username", dnsProvider);
                String clientIp = requireNamecheapClientIp();
                log.debug("Creating NamecheapDnsProvider");
                yield new NamecheapDnsProvider(apiUser, apiKey, username, clientIp);
            }
            // POWERDNS: legacy name still carried by in-flight messages and unmigrated credentials.
            case "CERTPING", "POWERDNS" -> {
                Map<String, String> fields = parseJson(rawCredential, dnsProvider);
                String apiKey = requireField(fields, "apiKey", dnsProvider);
                // A credential apiUrl is ignored: the base URL comes from the deployment, so a
                // credential cannot send the key to another host.
                String apiUrl = firstNonBlank(
                        certPingDnsApiUrlSupplier.get(),
                        CertPingDnsProvider.DEFAULT_API_BASE);
                log.debug("Creating CertPingDnsProvider");
                yield new CertPingDnsProvider(apiKey, apiUrl);
            }
            default -> throw new PermanentAgentException("DNS_PROVIDER_UNKNOWN",
                    "Unknown DNS provider: '" + dnsProvider + "'. Supported: CLOUDFLARE, AWS_ROUTE53, GODADDY, NAMEDOTCOM, HOSTINGER, NAMECHEAP, CERTPING (POWERDNS accepted as an alias)");
        };
    }

    private Map<String, String> parseJson(String rawCredential, String providerName) {
        try {
            return objectMapper.readValue(rawCredential, new TypeReference<>() {});
        } catch (Exception e) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    "Failed to parse " + providerName + " credential JSON: " + e.getMessage(), e);
        }
    }

    private String requireField(Map<String, String> fields, String field, String providerName) {
        String value = fields.get(field);
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    providerName + " credential missing required field: " + field);
        }
        return value;
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return null;
    }

    private String requireNamecheapClientIp() {
        String clientIp = namecheapClientIpSupplier.get();
        if (clientIp == null || clientIp.isBlank()) {
            throw new PermanentAgentException("DNS_CREDENTIAL_INVALID",
                    NAMECHEAP_CLIENT_IP_ENV + " env var is required for NAMECHEAP DNS provider");
        }
        return clientIp;
    }
}
