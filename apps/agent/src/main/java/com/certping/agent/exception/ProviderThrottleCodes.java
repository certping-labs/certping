// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import java.util.Set;

/**
 * Single source of truth for the per-provider throttle / rate-limit signals our adapters
 * recognise. Every entry is doc-cited so reviewers can verify the contract without grepping
 * each SDK.
 *
 * <p>Most adapters don't read these constants directly — they go through the typed
 * detectors on {@link RateLimitClassifier} ({@code fromAws}, {@code fromAzure},
 * {@code fromGcp}, {@code fromK8s}) which in turn use the SDK's own throttle accessors
 * (which themselves match the codes documented below). The constants are exposed here so
 * the rules are inspectable in code (not buried in third-party SDK internals) and so
 * adapters that need to extend detection — e.g. AWS Route53's two quirks — can do so by
 * referencing a named constant set with a doc link, not a magic string.
 *
 * <p>If a provider documents a new throttle code, update this file.
 */
public final class ProviderThrottleCodes {

    private ProviderThrottleCodes() {}

    // ─────────────────────────────────────────────────────────────────────────────
    //  AWS — docs:
    //  https://docs.aws.amazon.com/general/latest/gr/api-retries.html
    //  AWS SDK v2 RetryUtils source (THROTTLING_ERROR_CODES + RETRYABLE_STATUS_CODES):
    //  https://github.com/aws/aws-sdk-java-v2/blob/master/core/sdk-core/src/main/java/software/amazon/awssdk/core/internal/retry/SdkDefaultRetrySetting.java
    //
    //  AwsServiceException.isThrottlingException() returns true for all of these PLUS
    //  HTTP 429. Adapters should prefer that method; this set is what it covers.
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     * AWS-wide throttle error codes the SDK recognises. Captured here so adapters can
     * extend recognition for codes that arrive via non-throttle wrappers (e.g. Route53
     * returns {@code Throttling} at HTTP 400, which {@code isThrottlingException()}
     * misses — see {@link com.certping.agent.ssl.dns.AwsRoute53DnsProvider}).
     */
    public static final Set<String> AWS_THROTTLE_ERROR_CODES = Set.of(
            "Throttling",
            "ThrottlingException",
            "ThrottledException",
            "Throttled",
            "ProvisionedThroughputExceededException",
            "TooManyRequestsException",
            "TooManyRequests",
            "RequestLimitExceeded",
            "BandwidthLimitExceeded",
            "RequestThrottledException",
            "RequestThrottled",
            "SlowDown",
            "EC2ThrottledException",
            "PriorRequestNotComplete"  // Route53-specific in-flight overlap signal
    );

    // ─────────────────────────────────────────────────────────────────────────────
    //  Azure — docs:
    //  https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling
    //  Universal contract: HTTP 429 / 503 + Retry-After header.
    //  Specific data-plane services (KV, AGW, AFD) follow the same shape.
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     * Azure is consistent across ARM and data-plane: 429 (subscription / resource quota)
     * and 503 (transient maintenance / overload). Both carry {@code Retry-After}.
     */
    public static final Set<Integer> AZURE_THROTTLE_STATUSES = Set.of(429, 503);

    // ─────────────────────────────────────────────────────────────────────────────
    //  GCP — docs:
    //  https://cloud.google.com/apis/design/errors#error_retries
    //  https://cloud.google.com/certificate-manager/quotas
    //  gax exception hierarchy:
    //  https://cloud.google.com/java/docs/reference/gax/latest/com.google.api.gax.rpc.ApiException
    //
    //  Typed subclasses ResourceExhaustedException + UnavailableException carry the
    //  throttle signal. HTTP transport surfaces the same as 429 / 503.
    //  google.rpc.RetryInfo (when present in ErrorDetails) carries the precise retryDelay.
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     * gRPC status names that map to throttle / "please back off" semantics. We don't
     * compare these as strings (we use {@code instanceof ResourceExhaustedException}
     * etc.) — they're documented here for human reviewers.
     */
    public static final Set<String> GCP_THROTTLE_GRPC_CODES = Set.of(
            "RESOURCE_EXHAUSTED",
            "UNAVAILABLE"
    );

    /** GCP REST-transport throttle statuses (same as Azure / generic HTTP semantics). */
    public static final Set<Integer> GCP_THROTTLE_STATUSES = Set.of(429, 503);

    // ─────────────────────────────────────────────────────────────────────────────
    //  Kubernetes — docs:
    //  https://kubernetes.io/docs/concepts/cluster-administration/flow-control/
    //
    //  The API server's API Priority and Fairness layer rejects with HTTP 429 + the
    //  X-Kubernetes-PF-* headers. Admission webhooks may also throttle with 429.
    //  Either way the Java client surfaces it as ApiException with code=429.
    // ─────────────────────────────────────────────────────────────────────────────

    /** K8s apiserver flow-control rejection statuses. */
    public static final Set<Integer> K8S_THROTTLE_STATUSES = Set.of(429, 503);

    // ─────────────────────────────────────────────────────────────────────────────
    //  Let's Encrypt (ACME) — docs:
    //  https://letsencrypt.org/docs/rate-limits/
    //
    //  acme4j surfaces all rate-limit errors as AcmeRateLimitedException whose
    //  getRetryAfter() returns the documented capacity-restoration time. The
    //  503 + Retry-After "Overall Requests Limit" path comes via AcmeServerException;
    //  LetsEncrypt*Service maps both.
    // ─────────────────────────────────────────────────────────────────────────────

    /** Documented (but not enforced as enum) — for reviewer reference. */
    public static final Set<String> LE_RATE_LIMIT_KINDS = Set.of(
            "new-registrations-per-ip",         // 10 / 3h / IP
            "new-orders-per-account",           // 300 / 3h / account
            "new-certs-per-registered-domain",  // 50 / 7d / domain
            "new-certs-per-exact-identifier-set", // 5 / 7d / identifier set
            "authorization-failures-per-identifier", // 5 / 1h
            "consecutive-authorization-failures",    // 1152 lifetime
            "overall-requests-limit"            // per-endpoint per-IP
    );

    // ─────────────────────────────────────────────────────────────────────────────
    //  DigiCert CertCentral — docs:
    //  https://dev.digicert.com/en/certcentral-apis/services-api.html
    //
    //  Documented limit: 1000 req / 5 min / account. Throttle response: HTTP 429
    //  with documented body {"errors": [{"code": "request_limit_reached", ...}]}.
    //  No Retry-After header documented — our blind backoff applies.
    // ─────────────────────────────────────────────────────────────────────────────

    public static final Set<Integer> DIGICERT_THROTTLE_STATUSES = Set.of(429);
    public static final Set<String> DIGICERT_THROTTLE_BODY_CODES = Set.of(
            "request_limit_reached"
    );

    // ─────────────────────────────────────────────────────────────────────────────
    //  GlobalSign Atlas — docs:
    //  https://atlas.globalsign.com/api-docs (needs a GlobalSign Atlas account)
    //
    //  Throttle: HTTP 429 (account quota) or 503 (transient) — Retry-After header
    //  honored. GlobalSignAtlasClient.assert2xx handles both centrally.
    // ─────────────────────────────────────────────────────────────────────────────

    public static final Set<Integer> GLOBALSIGN_THROTTLE_STATUSES = Set.of(429, 503);

    // ─────────────────────────────────────────────────────────────────────────────
    //  DNS providers
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     * Cloudflare API — 1200 req / 5 min / user globally; per-endpoint sub-limits.
     * Doc: https://developers.cloudflare.com/fundamentals/api/reference/limits/
     * Returns HTTP 429 with lowercase {@code retry-after} header in seconds.
     */
    public static final Set<Integer> CLOUDFLARE_THROTTLE_STATUSES = Set.of(429);

    /**
     * AWS Route53 — 5 ChangeResourceRecordSets / sec / account.
     * Doc: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html
     * Surfaces as HTTP 400 (not 429!) with errorCode {@code Throttling}, or HTTP 400 with
     * {@code PriorRequestNotComplete} when an earlier change is still in-flight. Neither
     * is caught by {@code AwsServiceException.isThrottlingException()}, so
     * {@link com.certping.agent.ssl.dns.AwsRoute53DnsProvider#classifyRoute53Throttle}
     * checks {@link #AWS_THROTTLE_ERROR_CODES} explicitly.
     */
    public static final Set<String> ROUTE53_ADDITIONAL_THROTTLE_CODES = Set.of(
            "Throttling",
            "PriorRequestNotComplete"
    );

    /**
     * GoDaddy DNS — 60 req / min / endpoint.
     * Doc: https://developer.godaddy.com/doc
     * Returns HTTP 429 (Retry-After not documented — blind backoff).
     */
    public static final Set<Integer> GODADDY_THROTTLE_STATUSES = Set.of(429);

    /**
     * Name.com — 20 req / sec, 3000 req / hr.
     * Doc: https://www.name.com/api-docs
     * Returns HTTP 429 (Retry-After not documented — blind backoff).
     */
    public static final Set<Integer> NAMEDOTCOM_THROTTLE_STATUSES = Set.of(429);

    // ─────────────────────────────────────────────────────────────────────────────
    //  Edge / CDN providers
    // ─────────────────────────────────────────────────────────────────────────────

    /**
     * Akamai CPS — 35 req / min general, 20 req / 2 sec burst, 10 req / min for
     * "list active certificates".
     * Doc: https://techdocs.akamai.com/cps/reference/rate-limiting
     * Returns HTTP 429 + Retry-After.
     */
    public static final Set<Integer> AKAMAI_CPS_THROTTLE_STATUSES = Set.of(429);

    /**
     * F5 BIG-IP iControl REST — operator-configurable; no documented standard limit
     * since BIG-IP is typically a private appliance, not multi-tenant.
     * Doc: https://clouddocs.f5.com/api/icontrol-rest/
     * Returns HTTP 429 / 503 when configured.
     */
    public static final Set<Integer> F5_THROTTLE_STATUSES = Set.of(429, 503);

    /**
     * Cloudflare Edge SSL upload — same global rate-limit as Cloudflare API.
     * Doc: https://developers.cloudflare.com/fundamentals/api/reference/limits/
     */
    public static final Set<Integer> CLOUDFLARE_EDGE_THROTTLE_STATUSES = Set.of(429);

    // ─────────────────────────────────────────────────────────────────────────────
    //  Universal generic-HTTP throttle statuses — last-resort for any custom REST
    //  caller that needs to do an inline check (e.g. raw JDK HttpClient consumers).
    // ─────────────────────────────────────────────────────────────────────────────

    /** RFC 6585 + RFC 7231: 429 Too Many Requests, 503 Service Unavailable. */
    public static final Set<Integer> UNIVERSAL_THROTTLE_STATUSES = Set.of(429, 503);
}
