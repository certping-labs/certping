// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.google.api.gax.core.FixedCredentialsProvider;
import com.google.api.gax.rpc.ApiException;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.compute.v1.RegionTargetHttpsProxiesClient;
import com.google.cloud.compute.v1.RegionTargetHttpsProxiesSetSslCertificatesRequest;
import com.google.cloud.compute.v1.RegionTargetHttpsProxiesSettings;
import com.google.cloud.compute.v1.TargetHttpsProxiesClient;
import com.google.cloud.compute.v1.TargetHttpsProxiesSetSslCertificatesRequest;
import com.google.cloud.compute.v1.TargetHttpsProxy;
import com.google.cloud.compute.v1.TargetHttpsProxiesSettings;
import com.google.cloud.compute.v1.TargetSslProxiesClient;
import com.google.cloud.compute.v1.TargetSslProxiesSetSslCertificatesRequest;
import com.google.cloud.compute.v1.TargetSslProxy;
import com.google.cloud.compute.v1.TargetSslProxiesSettings;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@Component
public class GcpTargetProxyService {

    public GcpTargetProxyState fetchHttpsProxy(GcpTargetProxyConfig config, GoogleCredentials credentials) {
        if (config.isGlobal()) {
            try (TargetHttpsProxiesClient client = TargetHttpsProxiesClient.create(
                    TargetHttpsProxiesSettings.newBuilder()
                            .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                            .build())) {
                TargetHttpsProxy proxy = client.get(config.projectId(), config.targetProxyName());
                return new GcpTargetProxyState(
                        denormalizeFromCompute(proxy.getSslCertificatesList()), blankToNull(proxy.getCertificateMap()));
            } catch (Exception e) {
                if (e instanceof ApiException ae) {
                    Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                            RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                    if (rlt.isPresent()) {
                        throw rlt.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                    }
                }
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    throw rl.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                }
                throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                        "Failed to read Target HTTPS Proxy: " + e.getMessage(), e);
            }
        }

        try (RegionTargetHttpsProxiesClient client = RegionTargetHttpsProxiesClient.create(
            RegionTargetHttpsProxiesSettings.newBuilder()
                .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                .build())) {
            var proxy = client.get(config.projectId(), config.location(), config.targetProxyName());
            return new GcpTargetProxyState(
                    denormalizeFromCompute(proxy.getSslCertificatesList()), blankToNull(proxy.getCertificateMap()));
        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                    "Failed to read regional Target HTTPS Proxy: " + e.getMessage(), e);
        }
    }

    public void applyHttpsProxyCertificates(GcpTargetProxyConfig config,
                                            GoogleCredentials credentials,
                                            List<String> certificateResourceNames) {
        // Certificate Manager certificate resource names must carry the cross-service URL prefix
        // (//certificatemanager.googleapis.com/) when set on a Compute Target HTTPS Proxy —
        // without it Compute returns a 400 "Must be a valid SslCertificate URL or a valid
        // Certificate Manager certificate URL within the same scope and project".
        List<String> normalized = normalizeForCompute(certificateResourceNames);
        if (config.isGlobal()) {
            try (TargetHttpsProxiesClient client = TargetHttpsProxiesClient.create(
                    TargetHttpsProxiesSettings.newBuilder()
                            .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                            .build())) {
                TargetHttpsProxiesSetSslCertificatesRequest request =
                        TargetHttpsProxiesSetSslCertificatesRequest.newBuilder()
                                .addAllSslCertificates(normalized)
                                .build();
                client.setSslCertificatesAsync(config.projectId(), config.targetProxyName(), request).get();
                return;
            } catch (Exception e) {
                if (e instanceof ApiException ae) {
                    Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                            RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                    if (rlt.isPresent()) {
                        throw rlt.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                    }
                }
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    throw rl.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                }
                throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                        "Failed to update Target HTTPS Proxy: " + e.getMessage(), e);
            }
        }

        try (RegionTargetHttpsProxiesClient client = RegionTargetHttpsProxiesClient.create(
            RegionTargetHttpsProxiesSettings.newBuilder()
                .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                .build())) {
            RegionTargetHttpsProxiesSetSslCertificatesRequest request =
                    RegionTargetHttpsProxiesSetSslCertificatesRequest.newBuilder()
                            .addAllSslCertificates(normalized)
                            .build();
            client.setSslCertificatesAsync(config.projectId(), config.location(), config.targetProxyName(), request).get();
        } catch (Exception e) {
            if (e instanceof ApiException ae) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
            }
            throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                    "Failed to update regional Target HTTPS Proxy: " + e.getMessage(), e);
        }
    }

    public GcpTargetProxyState fetchSslProxy(GcpTargetProxyConfig config, GoogleCredentials credentials) {
        if (config.isGlobal()) {
            try (TargetSslProxiesClient client = TargetSslProxiesClient.create(
                    TargetSslProxiesSettings.newBuilder()
                            .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                            .build())) {
                TargetSslProxy proxy = client.get(config.projectId(), config.targetProxyName());
                return new GcpTargetProxyState(
                        denormalizeFromCompute(proxy.getSslCertificatesList()), blankToNull(proxy.getCertificateMap()));
            } catch (Exception e) {
                if (e instanceof ApiException ae) {
                    Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                            RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                    if (rlt.isPresent()) {
                        throw rlt.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                    }
                }
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    throw rl.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                }
                throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                        "Failed to read Target SSL Proxy: " + e.getMessage(), e);
            }
        }

        throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                "Regional Target SSL Proxy is not supported by the google-cloud-compute Java client in this build "
                        + "(no RegionTargetSslProxies API). Use a global Target SSL Proxy (location=global) for Proxy NLB "
                        + "or extend the agent when the SDK exposes regional target SSL proxies.");
    }

    public void applySslProxyCertificates(GcpTargetProxyConfig config,
                                          GoogleCredentials credentials,
                                          List<String> certificateResourceNames) {
        // Same Certificate Manager prefix requirement as HTTPS proxies — see normalizeForCompute().
        List<String> normalized = normalizeForCompute(certificateResourceNames);
        if (config.isGlobal()) {
            try (TargetSslProxiesClient client = TargetSslProxiesClient.create(
                    TargetSslProxiesSettings.newBuilder()
                            .setCredentialsProvider(FixedCredentialsProvider.create(credentials))
                            .build())) {
                TargetSslProxiesSetSslCertificatesRequest request =
                        TargetSslProxiesSetSslCertificatesRequest.newBuilder()
                                .addAllSslCertificates(normalized)
                                .build();
                client.setSslCertificatesAsync(config.projectId(), config.targetProxyName(), request).get();
                return;
            } catch (Exception e) {
                if (e instanceof ApiException ae) {
                    Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                            RateLimitClassifier.fromGcp(ae, "DEPLOY_PROVIDER_THROTTLED");
                    if (rlt.isPresent()) {
                        throw rlt.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                    }
                }
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    throw rl.get().toRetryable("gcp target-proxy update", config.targetProxyName(), e);
                }
                throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                        "Failed to update Target SSL Proxy: " + e.getMessage(), e);
            }
        }

        throw new PermanentAgentException("DEPLOY_GCP_PROXY_FAILED",
                "Regional Target SSL Proxy is not supported by the google-cloud-compute Java client in this build "
                        + "(no RegionTargetSslProxies API). Use a global Target SSL Proxy (location=global) for Proxy NLB "
                        + "or extend the agent when the SDK exposes regional target SSL proxies.");
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    /**
     * Canonical cross-service URL prefix the Compute API uses to identify Certificate Manager
     * certificates when referenced from {@code targetHttpsProxies.sslCertificates} /
     * {@code regionTargetHttpsProxies.sslCertificates} / {@code targetSslProxies.sslCertificates}.
     * This is the form we emit on the wire.
     */
    private static final String CERT_MANAGER_URL_PREFIX = "//certificatemanager.googleapis.com/";

    /**
     * Alternate Certificate Manager URL prefix that GCP also accepts on read paths (the proxy may
     * report existing entries in this form, especially on older resources). We must recognize it
     * for parity in canonicalization — otherwise the merge logic in
     * {@link GcpDeploymentSupport#mergeCertificateLists} would treat
     * {@code https://certificatemanager.googleapis.com/v1alpha1/projects/.../certificates/X} and
     * {@code projects/.../locations/.../certificates/X} as different entries even though they
     * point to the same logical resource, causing duplicate entries to accumulate on the proxy
     * across deploys until the per-proxy cert-list limit is hit.
     *
     * <p>Stored without the trailing {@code v1alpha1/} segment because GCP has shipped multiple
     * versioned variants ({@code v1alpha1}, {@code v1beta1}, {@code v1}). Recognition is by the
     * {@code https://certificatemanager.googleapis.com/} authority, then we tolerate any version
     * segment that follows.
     */
    private static final String CERT_MANAGER_HTTPS_AUTHORITY = "https://certificatemanager.googleapis.com/";

    /**
     * The Compute API's {@code sslCertificates[]} field accepts these URL shapes:
     * <ul>
     *   <li>Native compute SslCertificate: {@code projects/PROJECT/global/sslCertificates/NAME}
     *       or {@code projects/PROJECT/regions/REGION/sslCertificates/NAME} or the equivalent
     *       full self-link {@code https://www.googleapis.com/compute/v1/projects/...}.</li>
     *   <li>Certificate Manager certificate: canonical
     *       {@code //certificatemanager.googleapis.com/projects/PROJECT/locations/LOC/certificates/NAME},
     *       or HTTPS alternate
     *       {@code https://certificatemanager.googleapis.com/{vN}/projects/PROJECT/locations/LOC/certificates/NAME}.</li>
     * </ul>
     *
     * <p>Without one of these prefixes, Compute rejects a bare CM resource name with a misleading
     * "Must be a valid SslCertificate URL or a valid Certificate Manager certificate URL within the
     * same scope and project" 400 — because the bare path could ambiguously be parsed as either
     * kind, and Compute defaults to its own SslCertificate namespace (where the resource doesn't
     * exist).
     */

    /**
     * Normalize a list of cert resource identifiers into the form that
     * {@code setSslCertificates[]} accepts. Every Certificate Manager input (canonical, HTTPS
     * alternate, or bare resource name) is collapsed to the single canonical
     * {@link #CERT_MANAGER_URL_PREFIX} form. Native compute URLs and any other form pass through.
     * Null / blank entries are dropped.
     */
    static List<String> normalizeForCompute(List<String> resourceNames) {
        if (resourceNames == null || resourceNames.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>(resourceNames.size());
        for (String name : resourceNames) {
            if (name == null || name.isBlank()) continue;
            String trimmed = name.trim();
            String bareCertManager = stripCertManagerPrefix(trimmed);
            if (bareCertManager != null) {
                // Recognised as a CM URL in any of its forms → re-emit in the canonical form so
                // the proxy's stored entries always look identical across deploys (avoids drift).
                out.add(CERT_MANAGER_URL_PREFIX + bareCertManager);
            } else if (looksLikeCertManagerResourceName(trimmed)) {
                // Bare CM resource name (projects/.../locations/.../certificates/...) → prefix it.
                out.add(CERT_MANAGER_URL_PREFIX + trimmed);
            } else {
                // Native compute SslCertificate URL (full self-link or partial) or any other form
                // — pass through unchanged. Compute accepts both forms natively.
                out.add(trimmed);
            }
        }
        return out;
    }

    /**
     * Inverse of {@link #normalizeForCompute}: when the proxy reports back its current cert list,
     * strip <b>any</b> recognised Certificate Manager prefix so callers can compare against the
     * bare resource names we return from {@link GcpCertificateManagerService#createCertificate}.
     * Keeps merge / cleanup logic symmetric — it always works in the un-prefixed CM namespace
     * for CM entries, and in the unchanged form for compute entries.
     */
    static List<String> denormalizeFromCompute(List<String> rawFromProxy) {
        if (rawFromProxy == null || rawFromProxy.isEmpty()) {
            return new ArrayList<>();
        }
        List<String> out = new ArrayList<>(rawFromProxy.size());
        for (String raw : rawFromProxy) {
            if (raw == null) continue;
            String stripped = stripCertManagerPrefix(raw);
            out.add(stripped != null ? stripped : raw);
        }
        return out;
    }

    /**
     * If {@code value} is a Certificate Manager URL in any recognised form, return the bare
     * {@code projects/.../locations/.../certificates/...} suffix. Otherwise return {@code null}.
     *
     * <p>Recognised forms:
     * <ul>
     *   <li>{@code //certificatemanager.googleapis.com/<bare>} — canonical cross-service.</li>
     *   <li>{@code https://certificatemanager.googleapis.com/<version>/<bare>} — HTTPS alternate
     *       with any version segment (v1, v1beta1, v1alpha1, …) we don't pin.</li>
     * </ul>
     */
    static String stripCertManagerPrefix(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        if (trimmed.startsWith(CERT_MANAGER_URL_PREFIX)) {
            return trimmed.substring(CERT_MANAGER_URL_PREFIX.length());
        }
        if (trimmed.startsWith(CERT_MANAGER_HTTPS_AUTHORITY)) {
            // Skip the authority, then the version segment (e.g. "v1", "v1alpha1"), then the
            // separating slash. Anything beyond that is the bare resource name.
            String afterAuthority = trimmed.substring(CERT_MANAGER_HTTPS_AUTHORITY.length());
            int firstSlash = afterAuthority.indexOf('/');
            if (firstSlash > 0 && firstSlash < afterAuthority.length() - 1) {
                String maybeBare = afterAuthority.substring(firstSlash + 1);
                if (looksLikeCertManagerResourceName(maybeBare)) {
                    return maybeBare;
                }
            }
            // Authority matched but body didn't parse — fall through to null so the caller leaves
            // the value as-is rather than producing a corrupted canonical form.
        }
        return null;
    }

    /**
     * Heuristic: a Certificate Manager resource name has both {@code /locations/} (scoping segment)
     * and {@code /certificates/} (resource type segment). Native compute SslCertificate paths use
     * {@code /global/} or {@code /regions/} + {@code /sslCertificates/}, so they will never match.
     */
    static boolean looksLikeCertManagerResourceName(String value) {
        return value != null
                && value.contains("/locations/")
                && value.contains("/certificates/");
    }
}
