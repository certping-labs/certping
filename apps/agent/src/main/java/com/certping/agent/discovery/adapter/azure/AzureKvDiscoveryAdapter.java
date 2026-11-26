// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.azure;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.certificates.models.CertificatePolicy;
import com.azure.security.keyvault.certificates.models.KeyVaultCertificateWithPolicy;
import com.azure.security.keyvault.certificates.models.SubjectAlternativeNames;
import com.certping.agent.deployment.adapter.azure.AzureDeploymentAuthHelper;
import com.certping.agent.deployment.adapter.azure.AzureKvScope;
import com.certping.agent.deployment.adapter.azure.AzureScopeSupport;
import com.certping.agent.deployment.cloud.azure.AzureAuthMode;
import com.certping.agent.deployment.cloud.azure.AzureAuthScope;
import com.certping.agent.deployment.cloud.azure.AzureAuthSecret;
import com.certping.agent.deployment.cloud.azure.AzureCloudCredentialResolver;
import com.certping.agent.discovery.DiscoveryAdapter;
import com.certping.agent.discovery.DiscoveryAdapterFor;
import com.certping.agent.discovery.DiscoveryResult;
import com.certping.agent.model.message.DiscoveryFailedScope;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.credential.AzureKvDiscoveryCredential;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

/**
 * Discovers certificates stored in an Azure Key Vault.
 *
 * <p><b>Preferred (matches deployment):</b> {@code credentialScopeJson} carries
 * {@link AzureKvScope} ({@code authMode}, {@code tenantId}, {@code vaultUri}).
 * The KV secret at {@code deploymentCredHandle} carries only {@code clientId}/{@code clientSecret}
 * for {@link AzureAuthMode#SERVICE_PRINCIPAL}. For {@link AzureAuthMode#WORKLOAD_IDENTITY},
 * {@link DefaultAzureCredentialBuilder} is used (same as {@code AzureDeploymentAdapter}).
 *
 * <p><b>Legacy:</b> when {@code credentialScopeJson} is absent or blank, the secret is parsed as
 * {@link AzureKvDiscoveryCredential} (vault + tenant + optional SP in one JSON blob).
 */
@Slf4j
@Component
@DiscoveryAdapterFor(TargetType.AZURE_KV)
@RequiredArgsConstructor
public class AzureKvDiscoveryAdapter implements DiscoveryAdapter {

    private static final String CTX = "Azure KV Discovery";

    private final SecretStore                     secretStore;
    private final ObjectMapper                    objectMapper;
    private final AzureCloudCredentialResolver    azureCredentialResolver;

    @Override
    public List<DiscoveredCertEntry> discover(CertDiscoveryMessage message) {
        return discoverWithFailedScopes(message).certificates();
    }

    /**
     * Scans one vault. A vault that cannot be listed fails the whole scan. Certificates that are
     * listed but cannot be read (for example a missing certificates/get permission) make the scan
     * partial: the vault is reported in {@code failedScopes} so the server keeps their stored rows.
     */
    @Override
    public DiscoveryResult discoverWithFailedScopes(CertDiscoveryMessage message) {
        String effectiveVaultUri;
        TokenCredential tokenCredential;

        if (message.getCredentialScopeJson() != null && !message.getCredentialScopeJson().isBlank()) {
            AzureKvScope scope = parseScope(message.getCredentialScopeJson());
            AzureAuthMode authMode = AzureScopeSupport.parseAuthMode(scope.authMode(), CTX);
            validateScope(scope);
            effectiveVaultUri = scope.vaultUri().trim();

            if (authMode == AzureAuthMode.WORKLOAD_IDENTITY) {
                log.debug("{}: using DefaultAzureCredential (pod identity), vaultUri={}", CTX, effectiveVaultUri);
                tokenCredential = new DefaultAzureCredentialBuilder().build();
            } else {
                AzureAuthSecret kv = readDiscoveryKvSecret(message);
                AzureAuthScope authScope = AzureScopeSupport.toAuthScope(
                        scope.tenantId(), null, null, null);
                tokenCredential = azureCredentialResolver.resolve(authMode, authScope, kv, CTX);
            }

            log.info("Starting Azure KV discovery (scope-based): organizationId={}, vaultUri={}, authMode={}",
                    message.getOrganizationId(), effectiveVaultUri, authMode);
        } else {
            String credRaw = readSecretOrThrow(message);
            AzureKvDiscoveryCredential cred = AzureDeploymentAuthHelper.parseCredential(
                    objectMapper, credRaw, AzureKvDiscoveryCredential.class, CTX);
            validateLegacyCredential(cred);
            effectiveVaultUri = cred.getEffectiveVaultUri();

            if (cred.hasServicePrincipalCredentials()) {
                tokenCredential = AzureDeploymentAuthHelper.buildClientSecretCredentialValidated(
                        cred.getTenantId(), cred.getClientId(), cred.getClientSecret(), CTX);
            } else {
                tokenCredential = new DefaultAzureCredentialBuilder().build();
            }

            log.info("Starting Azure KV discovery (legacy secret): organizationId={}, vaultUri={}, authMode={}",
                    message.getOrganizationId(), effectiveVaultUri,
                    cred.hasServicePrincipalCredentials() ? "SERVICE_PRINCIPAL" : "WORKLOAD_IDENTITY");
        }

        CertificateClient client = buildClient(effectiveVaultUri, tokenCredential);
        List<String> unreadable = new ArrayList<>();
        List<DiscoveredCertEntry> entries = discoverCertificates(client, message.getOrganizationId(), unreadable);
        if (unreadable.isEmpty()) {
            return DiscoveryResult.complete(entries);
        }
        return new DiscoveryResult(entries, List.of(DiscoveryFailedScope.of(
                DiscoveryFailedScope.ScopeType.AZURE_VAULT, vaultName(effectiveVaultUri),
                "DISCOVERY_AZURE_KV_CERT_UNREADABLE",
                unreadable.size() + " certificate(s) were listed but could not be read (certificates/get): "
                        + String.join(", ", unreadable.subList(0, Math.min(5, unreadable.size()))))));
    }

    /** {@code https://my-vault.vault.azure.net/} becomes {@code my-vault}. */
    static String vaultName(String vaultUri) {
        if (vaultUri == null) {
            return null;
        }
        String host = vaultUri.trim().replaceFirst("^https?://", "");
        int slash = host.indexOf('/');
        if (slash >= 0) {
            host = host.substring(0, slash);
        }
        int dot = host.indexOf('.');
        return dot > 0 ? host.substring(0, dot) : host;
    }

    private String readSecretOrThrow(CertDiscoveryMessage message) {
        String path = message.getDeploymentCredHandle();
        if (path == null || path.isBlank()) {
            throw new PermanentAgentException("DISCOVERY_AZURE_KV_CREDENTIAL_INVALID",
                    CTX + " requires deploymentCredHandle when credentialScopeJson is blank");
        }
        return secretStore.read(path);
    }

    private AzureAuthSecret readDiscoveryKvSecret(CertDiscoveryMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AzureAuthSecret.empty();
        }
        return AzureScopeSupport.parseKvSecret(
                objectMapper, secretStore.read(message.getDeploymentCredHandle()), CTX);
    }

    private AzureKvScope parseScope(String json) {
        try {
            return objectMapper.readValue(json, AzureKvScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DISCOVERY_AZURE_KV_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private void validateScope(AzureKvScope scope) {
        AzureDeploymentAuthHelper.requireField("scope.vaultUri", scope.vaultUri(), CTX);
        String vaultUri = scope.vaultUri().trim();
        if (!vaultUri.matches("^https://[a-zA-Z0-9-]+\\.vault\\.azure\\.net/?$")) {
            throw new PermanentAgentException("DISCOVERY_AZURE_KV_CREDENTIAL_INVALID",
                    CTX + " scope.vaultUri has invalid format: " + vaultUri);
        }
    }

    // Package-private for testing — allows injecting a mock CertificateClient.
    List<DiscoveredCertEntry> discoverCertificates(CertificateClient client, String organizationId) {
        return discoverCertificates(client, organizationId, new ArrayList<>());
    }

    /**
     * Lists and reads every certificate in the vault. Names that are listed but cannot be read are
     * added to {@code unreadableNames} instead of being dropped silently.
     */
    List<DiscoveredCertEntry> discoverCertificates(CertificateClient client, String organizationId,
            List<String> unreadableNames) {
        try {
            List<DiscoveredCertEntry> entries = new ArrayList<>();

            for (var props : listProperties(client)) {
                try {
                    KeyVaultCertificateWithPolicy cert = client.getCertificate(props.getName());
                    entries.add(toDiscoveredCertEntry(cert));
                } catch (Exception e) {
                    unreadableNames.add(props.getName());
                    log.warn("Failed to fetch Azure KV certificate name={}: {} - reported as a failed scope",
                            props.getName(), e.getMessage());
                }
            }

            log.info("Found {} Azure KV certificates for organizationId={}", entries.size(), organizationId);
            return entries;

        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            if (msg.contains("AuthenticationFailed") || msg.contains("Forbidden")
                    || msg.contains("401") || msg.contains("403")) {
                throw new PermanentAgentException("DISCOVERY_AZURE_KV_ACCESS_DENIED",
                        "Azure KV access denied for organizationId=" + organizationId + ": " + msg, e);
            }
            throw new TransientAgentException("DISCOVERY_AZURE_KV_ERROR",
                    "Azure KV discovery failed: " + msg, e);
        }
    }

    // Package-private for testing — returns list so tests can inject without mocking PagedIterable.
    List<com.azure.security.keyvault.certificates.models.CertificateProperties> listProperties(
            CertificateClient client) {
        List<com.azure.security.keyvault.certificates.models.CertificateProperties> result = new ArrayList<>();
        client.listPropertiesOfCertificates().forEach(result::add);
        return result;
    }

    // Package-private for testing.
    CertificateClient buildClient(String vaultUri, TokenCredential credential) {
        return new CertificateClientBuilder()
                .vaultUrl(vaultUri)
                .credential(credential)
                .buildClient();
    }

    private DiscoveredCertEntry toDiscoveredCertEntry(KeyVaultCertificateWithPolicy cert) {
        CertificatePolicy policy = cert.getPolicy();

        String domain         = extractDomain(policy);
        List<String> sanList  = extractSans(policy);
        String notBefore      = formatDateTime(cert.getProperties().getNotBefore());
        String notAfter       = formatDateTime(cert.getProperties().getExpiresOn());
        String certStatus     = mapCertStatus(cert);

        // The KV policy API exposes neither the serial number nor the signature
        // algorithm, but the raw certificate bytes carry both. Parsing them lets a
        // discovered Azure cert be cross-referenced against CertPing-issued certs by
        // serial number. Serial is emitted as upper-case hex (no separators) to match
        // the format the issuance path stores.
        X509Certificate x509  = parseCertificate(cert.getCer(), cert.getId());
        String serialNumber   = x509 != null
                ? x509.getSerialNumber().toString(16).toUpperCase() : null;
        String signatureAlgo  = x509 != null ? x509.getSigAlgName() : null;

        return DiscoveredCertEntry.builder()
                .resourceId(cert.getId())
                .domain(domain)
                .subjectDn(policy != null ? policy.getSubject() : null)
                .sanDomains(sanList.isEmpty() ? null : sanList)
                .keyAlgorithm(policy != null && policy.getKeyType() != null
                        ? policy.getKeyType().toString() : null)
                .signatureAlgorithm(signatureAlgo)
                .notBefore(notBefore)
                .notAfter(notAfter)
                .issuer(policy != null ? policy.getIssuerName() : null)
                .serialNumber(serialNumber)
                .certStatus(certStatus)
                .inUseBy(List.of())
                .keyUsage(null)             // Not available via KV API
                .extendedKeyUsage(null)     // Not available via KV API
                .certType("IMPORTED")
                .build();
    }

    private String extractDomain(CertificatePolicy policy) {
        if (policy == null) return null;
        // Prefer SAN DNS entries, fall back to subject CN
        SubjectAlternativeNames sans = policy.getSubjectAlternativeNames();
        if (sans != null && sans.getDnsNames() != null) {
            for (String dns : sans.getDnsNames()) {
                if (dns != null && !dns.isBlank()) return dns;
            }
        }
        String subject = policy.getSubject();
        if (subject != null && subject.contains("CN=")) {
            String cn = subject.substring(subject.indexOf("CN=") + 3);
            int comma = cn.indexOf(',');
            return comma > 0 ? cn.substring(0, comma).trim() : cn.trim();
        }
        return subject;
    }

    private List<String> extractSans(CertificatePolicy policy) {
        if (policy == null) return List.of();
        SubjectAlternativeNames sans = policy.getSubjectAlternativeNames();
        if (sans == null) return List.of();
        List<String> result = new ArrayList<>();
        if (sans.getDnsNames() != null) sans.getDnsNames().forEach(result::add);
        if (sans.getEmails()   != null) sans.getEmails().forEach(result::add);
        return result;
    }

    private String formatDateTime(OffsetDateTime dt) {
        return dt != null ? dt.toString() : null;
    }

    /**
     * Parses raw DER certificate bytes into an {@link X509Certificate}. Returns null
     * (and logs) when the bytes are absent or unparseable, so discovery still records
     * the cert with whatever metadata the policy API provided.
     */
    private X509Certificate parseCertificate(byte[] cer, String id) {
        if (cer == null || cer.length == 0) {
            return null;
        }
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cer));
        } catch (CertificateException e) {
            log.warn("{}: failed to parse raw certificate bytes for {}: {} — serial/signature left null",
                    CTX, id, e.getMessage());
            return null;
        }
    }

    /**
     * Maps an Azure KV certificate to a {@code certStatus} value consistent with the
     * statuses emitted by the AWS ACM adapter and recognised by the CertPing UI
     * filter dropdown (ISSUED / EXPIRED / INACTIVE / UNKNOWN).
     *
     * <p>Azure KV's data model only exposes an {@code enabled} flag and the validity
     * window — it does not carry a native "issued/revoked" state — so this mapping is
     * derived from those two signals.
     */
    private String mapCertStatus(KeyVaultCertificateWithPolicy cert) {
        Boolean enabled       = cert.getProperties().isEnabled();
        OffsetDateTime expiry = cert.getProperties().getExpiresOn();
        OffsetDateTime nowUtc = OffsetDateTime.now(ZoneOffset.UTC);

        if (expiry != null && expiry.isBefore(nowUtc)) {
            return "EXPIRED";
        }
        if (Boolean.FALSE.equals(enabled)) {
            return "INACTIVE";
        }
        if (Boolean.TRUE.equals(enabled) && expiry != null) {
            return "ISSUED";
        }
        return "UNKNOWN";
    }

    private void validateLegacyCredential(AzureKvDiscoveryCredential cred) {
        AzureDeploymentAuthHelper.requireField("vaultUri (or allowedVaults)",
                cred.getEffectiveVaultUri(), CTX);
        AzureDeploymentAuthHelper.requireField("tenantId", cred.getTenantId(), CTX);
        // clientId/clientSecret are optional — absent means workload identity is used
    }
}
