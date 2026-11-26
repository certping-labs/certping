// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.aws;

import com.certping.agent.discovery.DiscoveryAdapter;
import com.certping.agent.discovery.DiscoveryAdapterFor;
import com.certping.agent.discovery.DiscoveryResult;
import com.certping.agent.model.message.DiscoveryFailedScope;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import com.certping.agent.deployment.adapter.aws.AwsAcmScope;
import com.certping.agent.deployment.adapter.aws.AwsScopeSupport;
import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthScope;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.ssl.CertificateMetadata;
import com.certping.agent.ssl.CertificateMetadataExtractor;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.acm.model.AcmException;
import software.amazon.awssdk.services.acm.model.CertificateDetail;
import software.amazon.awssdk.services.acm.model.CertificateStatus;
import software.amazon.awssdk.services.acm.model.DescribeCertificateRequest;
import software.amazon.awssdk.services.acm.model.ExtendedKeyUsage;
import software.amazon.awssdk.services.acm.model.GetCertificateRequest;
import software.amazon.awssdk.services.acm.model.KeyUsage;
import software.amazon.awssdk.services.acm.model.ListCertificatesRequest;
import software.amazon.awssdk.services.acm.model.ListCertificatesResponse;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Discovers certificates stored in AWS Certificate Manager (ACM).
 *
 * <p>Uses the same scope-based AWS auth model as deployment:
 * {@code credentialScopeJson} carries region/auth mode and {@code deploymentCredHandle}
 * carries only optional sensitive bootstrap keys.
 */
@Slf4j
@Component
@DiscoveryAdapterFor({TargetType.AWS_ACM, TargetType.AWS_ALB, TargetType.AWS_NLB,
        TargetType.AWS_CLOUDFRONT, TargetType.AWS_API_GW_REST, TargetType.AWS_API_GW_HTTP})
@RequiredArgsConstructor
public class AwsAcmDiscoveryAdapter implements DiscoveryAdapter {

    private static final String CTX = "AWS ACM Discovery";

    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final AwsCloudCredentialResolver awsCredentialResolver;

    @Override
    public List<DiscoveredCertEntry> discover(CertDiscoveryMessage message) {
        return discoverWithFailedScopes(message).certificates();
    }

    /**
     * Scans one region. A failure to list the region fails the whole scan (there is nothing else
     * to report). Certificates that are listed but cannot be described make the scan partial: the
     * region is reported in {@code failedScopes} so the server keeps their stored rows.
     */
    @Override
    public DiscoveryResult discoverWithFailedScopes(CertDiscoveryMessage message) {
        AwsAcmScope scope = parseScope(message.getCredentialScopeJson());
        AwsAuthMode authMode = AwsScopeSupport.parseAuthMode(scope.authMode(), CTX);
        validateScope(scope);

        AwsAuthSecret credentialSecret = readCredentialSecret(message);
        AwsAuthScope authScope = AwsScopeSupport.toAuthScope(
                scope.region(), scope.roleArn(), scope.externalId());
        AwsCredentialsProvider credentialsProvider = awsCredentialResolver.resolve(
                authMode, authScope, credentialSecret, CTX);

        log.info("Starting ACM discovery: organizationId={}, authMode={}, region={}",
                message.getOrganizationId(), authMode, scope.region());

        try (AcmClient acmClient = buildClient(scope.region(), credentialsProvider)) {
            List<String> unreadable = new ArrayList<>();
            List<DiscoveredCertEntry> entries = discoverCertificates(acmClient, message.getOrganizationId(), unreadable);
            if (unreadable.isEmpty()) {
                return DiscoveryResult.complete(entries);
            }
            return new DiscoveryResult(entries, List.of(describeFailure(scope.region().trim(), unreadable)));

        } catch (PermanentAgentException | TransientAgentException e) {
            throw e;
        } catch (AcmException e) {
            String code = e.awsErrorDetails() != null ? e.awsErrorDetails().errorCode() : "unknown";
            if ("AccessDeniedException".equals(code) || "AuthorizationError".equals(code)) {
                throw new PermanentAgentException("DISCOVERY_ACM_ACCESS_DENIED",
                        "ACM ListCertificates denied for organizationId=" + message.getOrganizationId()
                        + ": " + e.getMessage(), e);
            }
            throw new TransientAgentException("DISCOVERY_ACM_ERROR",
                    "ACM ListCertificates failed: " + e.getMessage(), e);
        } catch (SdkException e) {
            throw new TransientAgentException("DISCOVERY_AWS_SDK_ERROR",
                    "AWS SDK error during ACM discovery: " + e.getMessage(), e);
        }
    }

    // Package-private for tests.
    List<DiscoveredCertEntry> discoverCertificates(AcmClient acmClient, String organizationId) {
        return discoverCertificates(acmClient, organizationId, new ArrayList<>());
    }

    /**
     * Lists and describes every certificate in the client's region. ARNs that are listed but
     * cannot be described are added to {@code unreadableArns} instead of being dropped silently.
     */
    List<DiscoveredCertEntry> discoverCertificates(AcmClient acmClient, String organizationId,
            List<String> unreadableArns) {
        List<String> arns = listAllCertificateArns(acmClient);
        log.info("Found {} ACM certificates for organizationId={}", arns.size(), organizationId);

        List<DiscoveredCertEntry> entries = new ArrayList<>(arns.size());
        for (String arn : arns) {
            try {
                CertificateDetail detail = acmClient.describeCertificate(
                        DescribeCertificateRequest.builder().certificateArn(arn).build()
                ).certificate();
                entries.add(toDiscoveredCertEntry(acmClient, detail));
            } catch (AcmException e) {
                unreadableArns.add(arn);
                log.warn("Failed to describe ACM certificate arn={}: {} - reported as a failed scope", arn, e.getMessage());
            }
        }
        return entries;
    }

    /** The region scope for certificates that were listed but could not be described. */
    static DiscoveryFailedScope describeFailure(String region, List<String> unreadableArns) {
        String account = accountFromArn(unreadableArns.get(0));
        String scopeId = account == null ? region : account + "/" + region;
        return DiscoveryFailedScope.of(DiscoveryFailedScope.ScopeType.AWS_REGION, scopeId,
                "DISCOVERY_ACM_DESCRIBE_FAILED",
                unreadableArns.size() + " ACM certificate(s) were listed but could not be read (acm:DescribeCertificate)");
    }

    /** The account ID in an ARN such as {@code arn:aws:acm:us-east-1:123456789012:certificate/x}, or null. */
    static String accountFromArn(String arn) {
        if (arn == null) {
            return null;
        }
        String[] parts = arn.split(":", 6);
        return parts.length >= 5 && parts[4].matches("\\d{12}") ? parts[4] : null;
    }

    /**
     * A stable error code for an AWS failure: {@code deniedCode} when AWS refused access
     * (AccessDenied, AuthorizationError, UnrecognizedClient and similar), {@code otherCode} otherwise.
     */
    static String errorCodeFor(Throwable e, String deniedCode, String otherCode) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            String code = null;
            if (t instanceof AwsServiceException ase && ase.awsErrorDetails() != null) {
                code = ase.awsErrorDetails().errorCode();
            }
            String text = (code != null ? code : "") + " " + (t.getMessage() != null ? t.getMessage() : "");
            if (text.contains("AccessDenied") || text.contains("AuthorizationError")
                    || text.contains("UnrecognizedClient") || text.contains("not authorized")) {
                return deniedCode;
            }
        }
        return otherCode;
    }

    // Package-private for tests.
    AcmClient buildClient(String region, AwsCredentialsProvider credentialsProvider) {
        return AcmClient.builder()
                .region(Region.of(region))
                .credentialsProvider(credentialsProvider)
                .build();
    }

    private List<String> listAllCertificateArns(AcmClient acmClient) {
        List<String> arns = new ArrayList<>();
        String nextToken = null;
        do {
            ListCertificatesRequest.Builder requestBuilder = ListCertificatesRequest.builder();
            if (nextToken != null) {
                requestBuilder.nextToken(nextToken);
            }
            ListCertificatesResponse response = acmClient.listCertificates(requestBuilder.build());
            response.certificateSummaryList().forEach(summary -> arns.add(summary.certificateArn()));
            nextToken = response.nextToken();
        } while (nextToken != null);
        return arns;
    }

    private DiscoveredCertEntry toDiscoveredCertEntry(AcmClient acmClient, CertificateDetail detail) {
        List<String> inUseBy = detail.inUseBy() != null ? detail.inUseBy() : List.of();
        List<String> sans    = detail.subjectAlternativeNames() != null
                ? detail.subjectAlternativeNames() : List.of();

        // ACM exposes keyAlgorithm directly for most certs, but leaves it empty for some
        // (notably imported certs). When it's blank, fall back to fetching the leaf via
        // GetCertificate and deriving the algorithm from the public key. The fallback is
        // best-effort: any failure (e.g. missing acm:GetCertificate permission) leaves the
        // value null rather than failing the scan.
        String keyAlgorithm = blankToNull(detail.keyAlgorithmAsString());
        if (keyAlgorithm == null && CertificateStatus.ISSUED.equals(detail.status())) {
            keyAlgorithm = resolveKeyAlgorithmFromLeaf(acmClient, detail.certificateArn());
        }

        String keyUsage = detail.keyUsages() != null
                ? detail.keyUsages().stream()
                        .map(KeyUsage::nameAsString)
                        .collect(Collectors.joining(","))
                : null;

        String extendedKeyUsage = detail.extendedKeyUsages() != null
                ? detail.extendedKeyUsages().stream()
                        .map(ExtendedKeyUsage::nameAsString)
                        .filter(name -> name != null && !name.isBlank() && !"NONE".equals(name))
                        .collect(Collectors.joining(","))
                : null;

        return DiscoveredCertEntry.builder()
                .resourceId(detail.certificateArn())
                .domain(detail.domainName())
                .subjectDn(detail.subject())
                .sanDomains(sans.isEmpty() ? null : sans)
                .keyAlgorithm(keyAlgorithm)
                .signatureAlgorithm(detail.signatureAlgorithm())
                .notBefore(detail.notBefore() != null ? detail.notBefore().toString() : null)
                .notAfter(detail.notAfter() != null ? detail.notAfter().toString() : null)
                .issuer(detail.issuer())
                .serialNumber(detail.serial())
                .certStatus(detail.status() != null ? detail.status().toString() : null)
                .inUseBy(inUseBy)
                .keyUsage(keyUsage)
                .extendedKeyUsage(extendedKeyUsage != null && extendedKeyUsage.isBlank() ? null : extendedKeyUsage)
                .certType(detail.type() != null ? detail.type().toString() : null)
                .build();
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value;
    }

    /**
     * Best-effort derivation of the key algorithm from the issued leaf certificate, used
     * when ACM's {@code keyAlgorithm} field is empty. Fetches the leaf via GetCertificate
     * and reads the public key. Returns the ACM-style {@code ALGO_size} form (e.g.
     * {@code RSA_2048}, matching ACM's native enum) when the size is known, or null on any
     * failure — discovery must still succeed even if this org's role lacks
     * {@code acm:GetCertificate}.
     */
    private String resolveKeyAlgorithmFromLeaf(AcmClient acmClient, String arn) {
        try {
            String pem = acmClient.getCertificate(
                    GetCertificateRequest.builder().certificateArn(arn).build()).certificate();
            if (pem == null || pem.isBlank()) {
                return null;
            }
            X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
            CertificateMetadata meta = CertificateMetadataExtractor.fromLeaf(leaf);
            if (meta.publicKeyAlgorithm() == null) {
                return null;
            }
            // Use the same ALGO_size shape ACM reports natively (e.g. RSA_2048) so the
            // discovery table doesn't mix "RSA_2048" and "RSA-2048" for the same column.
            return meta.keySize() != null
                    ? meta.publicKeyAlgorithm() + "_" + meta.keySize()
                    : meta.publicKeyAlgorithm();
        } catch (Exception e) {
            log.debug("{}: could not derive keyAlgorithm from leaf for arn={}: {}",
                    CTX, arn, e.getMessage());
            return null;
        }
    }

    private AwsAcmScope parseScope(String credentialScopeJson) {
        if (credentialScopeJson == null || credentialScopeJson.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(credentialScopeJson, AwsAcmScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private void validateScope(AwsAcmScope scope) {
        if (scope.region() == null || scope.region().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScopeJson.region is required");
        }
    }

    private AwsAuthSecret readCredentialSecret(CertDiscoveryMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AwsAuthSecret.empty();
        }
        String credRaw = secretStore.read(message.getDeploymentCredHandle());
        return AwsScopeSupport.parseKvSecret(objectMapper, credRaw, CTX);
    }
}
