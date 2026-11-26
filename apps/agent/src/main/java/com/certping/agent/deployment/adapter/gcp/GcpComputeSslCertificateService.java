// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.api.gax.rpc.ApiException;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.compute.v1.RegionSslCertificatesClient;
import com.google.cloud.compute.v1.RegionSslCertificatesSettings;
import com.google.cloud.compute.v1.SslCertificate;
import com.google.cloud.compute.v1.SslCertificateSelfManagedSslCertificate;
import com.google.cloud.compute.v1.SslCertificatesClient;
import com.google.cloud.compute.v1.SslCertificatesSettings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

/**
 * Manages native {@code compute.sslCertificates} (global) and {@code compute.regionSslCertificates}
 * resources.
 *
 * <p>Used by the target-proxy deployment targets: GCP_ALB, GCP_API_GW and GCP_CLOUD_CDN (Target
 * HTTPS Proxies) and GCP_PROXY_NLB (Target SSL Proxies). Both proxy types reject Certificate
 * Manager certificate references on setSslCertificates.
 *
 * <p><b>Immutability</b>: a Compute {@code SslCertificate} is immutable — there is no update API.
 * The lifecycle is always create-new → swap on the Target Proxy → delete the prior resource. There
 * is no equivalent of {@link GcpCertificateManagerService#updateCertificate} here.
 */
@Slf4j
@Component
public class GcpComputeSslCertificateService {

    /**
     * Creates a self-managed SslCertificate and returns its full self-link. A regional proxy only
     * accepts a regional SslCertificate in its own region, so a non-global {@code location}
     * creates the certificate in that region.
     */
    public String createSslCertificate(String projectId,
                                       String location,
                                       String certificateId,
                                       CertificateBundle bundle,
                                       GoogleCredentials credentials) {
        boolean regional = !GcpTargetProxyConfig.isGlobalLocation(location);
        String certPem = selectCertificatePem(bundle);
        String keyPem = requirePrivateKey(bundle.privateKey());

        // Use the nested `selfManaged` shape — required by GCP when `type=SELF_MANAGED` is set
        // explicitly. The legacy top-level `certificate` / `privateKey` fields are still on the
        // proto for backward compatibility, but the Compute API rejects them with
        // "resource.selfManaged: ''. Self-managed certificate details must be specified if
        // type = SELF_MANAGED" if `type` is set without the nested object also being populated.
        //
        // In the google-cloud-compute Java SDK the nested type is flattened to a top-level class
        // named SslCertificateSelfManagedSslCertificate (NOT a nested SslCertificate.SelfManaged
        // inner class — that flat naming is how protoc-generated Java handles GCP's nested protos).
        SslCertificate body = SslCertificate.newBuilder()
                .setName(certificateId)
                .setType("SELF_MANAGED")
                .setSelfManaged(SslCertificateSelfManagedSslCertificate.newBuilder()
                        .setCertificate(certPem)
                        .setPrivateKey(keyPem)
                        .build())
                .build();

        try {
            // insertAsync blocks via .get() on the longrunning operation — keeps the deploy flow
            // synchronous so callers see the resource exists before the proxy swap.
            if (regional) {
                try (RegionSslCertificatesClient client = RegionSslCertificatesClient.create(
                        RegionSslCertificatesSettings.newBuilder()
                                .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                                .build())) {
                    client.insertAsync(projectId, location, body).get();
                }
            } else {
                try (SslCertificatesClient client = SslCertificatesClient.create(
                        SslCertificatesSettings.newBuilder()
                                .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                                .build())) {
                    client.insertAsync(projectId, body).get();
                }
            }
            // Return the canonical full self-link. GCP's setSslCertificates accepts both partial
            // (projects/.../global/sslCertificates/NAME) and full URL forms, but the full self-link
            // is what the API echoes back on .get(...), so using it here keeps round-tripping
            // symmetric — fetched cert lists and freshly-created cert URLs are byte-identical.
            String selfLink = "https://www.googleapis.com/compute/v1/projects/"
                    + projectId + (regional ? "/regions/" + location : "/global")
                    + "/sslCertificates/" + certificateId;
            log.debug("Created compute SslCertificate: {}", selfLink);
            return selfLink;
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            // A hard SSL-certificate quota (per-project allocation cap) is PERMANENT — it clears only
            // by deleting certs or raising the quota, never by retrying. Classify it BEFORE the
            // throttle classifier, which otherwise treats the RESOURCE_EXHAUSTED/429 as a transient
            // rate-limit and retries until give-up. Requires an explicit quota marker (not a bare
            // RESOURCE_EXHAUSTED), so genuine rate-limits still fall through to the retry path below.
            if (isSslCertificateQuotaExceeded(e)) {
                throw new PermanentAgentException("DEPLOY_GCP_QUOTA_EXCEEDED",
                        "GCP project SSL-certificate quota exceeded (compute.sslCertificates — default "
                                + "limit is 10 per project). Remove unused SSL certificates from the project "
                                + "or request a quota increase, then retry. Underlying error: " + e.getMessage(), e);
            }
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp compute SSL upsert", certificateId, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp compute SSL upsert", certificateId, e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_SSL_CERT_FAILED",
                    "Compute SslCertificate create failed: " + e.getMessage(), e);
        }
    }

    /**
     * Detects a <b>hard</b> SSL-certificate quota failure (per-project allocation cap) from an
     * explicit quota marker anywhere in the cause chain.
     *
     * <p>Deliberately narrow: it does <b>not</b> treat a bare {@code RESOURCE_EXHAUSTED} status /
     * 429 as quota, because GCP also uses that for transient rate-limiting — those must stay
     * retryable via {@link RateLimitClassifier}. It only fires on an unambiguous allocation-quota
     * signal ({@code QUOTA_EXCEEDED} / the {@code SSL_CERTIFICATES} metric + a limit).
     *
     * <p><b>Limitation:</b> GCP's Compute long-running-operation layer sometimes surfaces the quota
     * failure as a bare {@code PermissionDeniedException}/FORBIDDEN, dropping the structured quota
     * detail entirely. In that case there is no marker to match, this returns false, and the caller
     * falls back to {@code DEPLOY_GCP_SSL_CERT_FAILED}. The accumulation fix (lineage pruning) is the
     * real remedy — it keeps the project from reaching the cap in the first place.
     */
    static boolean isSslCertificateQuotaExceeded(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            String msg = c.getMessage();
            if (msg != null) {
                String upper = msg.toUpperCase(Locale.ROOT);
                if (upper.contains("QUOTA_EXCEEDED")
                        || upper.contains("QUOTAEXCEEDED")
                        || (upper.contains("SSL_CERTIFICATES") && upper.contains("LIMIT"))) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Deletes a global or regional SslCertificate. Tolerant of partial-resource-name input (e.g.
     * {@code projects/P/global/sslCertificates/NAME}) — pulls the scope and name segments out and
     * issues the delete by short name + project (+ region). Errors are logged and swallowed — callers should
     * only invoke this after the proxy no longer references the cert, so a failed delete is a leak
     * (visible in GCP), not a deployment failure.
     */
    public void deleteSslCertificate(String resourceName, GoogleCredentials credentials) {
        if (resourceName == null || resourceName.isBlank()) {
            return;
        }
        ParsedSslCertName parsed = parseSslCertResourceName(resourceName);
        if (parsed == null) {
            log.warn("Skipping compute SslCertificate delete — unrecognized resource name: {}", resourceName);
            return;
        }
        try {
            if (parsed.region() != null) {
                try (RegionSslCertificatesClient client = RegionSslCertificatesClient.create(
                        RegionSslCertificatesSettings.newBuilder()
                                .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                                .build())) {
                    client.deleteAsync(parsed.projectId(), parsed.region(), parsed.certName()).get();
                }
            } else {
                try (SslCertificatesClient client = SslCertificatesClient.create(
                        SslCertificatesSettings.newBuilder()
                                .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                                .build())) {
                    client.deleteAsync(parsed.projectId(), parsed.certName()).get();
                }
            }
            log.debug("Deleted compute SslCertificate: {}", resourceName);
        } catch (Exception e) {
            // Don't fail the deployment over a cleanup miss — the cert is no longer attached
            // to the proxy, so this is a resource leak in GCP rather than a functional problem.
            log.warn("Failed to delete compute SslCertificate '{}' — leaving in place. Cause: {}",
                    resourceName, e.getMessage());
        }
    }

    /**
     * Parses any of these shapes → {@code (PROJECT, REGION, NAME)}, with a null region for global:
     * <ul>
     *   <li>{@code https://www.googleapis.com/compute/v1/projects/PROJECT/global/sslCertificates/NAME}
     *       — canonical self-link form, what {@link #createSslCertificate} returns and what
     *       {@code SslCertificate.selfLink} fields contain.</li>
     *   <li>{@code projects/PROJECT/global/sslCertificates/NAME} — partial-resource form, also
     *       accepted by GCP and possibly stored from older deploy runs.</li>
     *   <li>The regional forms of both, with {@code regions/REGION} in place of {@code global}.</li>
     * </ul>
     * Returns null for any other shape (e.g. a Certificate Manager resource name that snuck into
     * configJson from a prior adapter version) — callers should log-and-skip on null so a stale
     * prior name doesn't poison the cleanup path.
     */
    private static ParsedSslCertName parseSslCertResourceName(String resourceName) {
        String trimmed = resourceName.trim();
        // Strip the canonical compute selfLink prefix if present, leaving the partial form.
        String COMPUTE_PREFIX = "https://www.googleapis.com/compute/v1/";
        if (trimmed.startsWith(COMPUTE_PREFIX)) {
            trimmed = trimmed.substring(COMPUTE_PREFIX.length());
        }
        String[] parts = trimmed.split("/");
        // Expected: ["projects", PROJECT, "global", "sslCertificates", NAME]
        if (parts.length == 5
                && "projects".equals(parts[0])
                && "global".equals(parts[2])
                && "sslCertificates".equals(parts[3])) {
            return new ParsedSslCertName(parts[1], null, parts[4]);
        }
        // Regional: ["projects", PROJECT, "regions", REGION, "sslCertificates", NAME]
        if (parts.length == 6
                && "projects".equals(parts[0])
                && "regions".equals(parts[2])
                && "sslCertificates".equals(parts[4])) {
            return new ParsedSslCertName(parts[1], parts[3], parts[5]);
        }
        return null;
    }

    private record ParsedSslCertName(String projectId, String region, String certName) {}

    private String selectCertificatePem(CertificateBundle bundle) {
        if (bundle.fullChain() != null && !bundle.fullChain().isBlank()) {
            return bundle.fullChain();
        }
        return bundle.leafCertificate();
    }

    private String requirePrivateKey(String keyPem) {
        if (keyPem == null || keyPem.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CERT_INVALID",
                    "Certificate bundle missing private key for GCP compute SslCertificate");
        }
        return keyPem;
    }
}
