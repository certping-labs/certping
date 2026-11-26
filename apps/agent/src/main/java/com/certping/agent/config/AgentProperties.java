// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "agent")
public class AgentProperties {

    /** Numeric organization id this agent instance serves. */
    private String organizationId;
    /** Human-readable org slug for logging and observability only. */
    private String organizationSlug;
    /**
     * True for the agent shipped with the server (all-in-one image, compose bundle, certping chart
     * bundledAgent), from CERTPING_AGENT_BUNDLED. Reported on the Agents page only.
     */
    private boolean bundled;

    private TransportProperties  transport  = new TransportProperties();
    private RetryProperties       retry      = new RetryProperties();
    private KeyVaultProperties   keyvault   = new KeyVaultProperties();
    private AcmeProperties       acme       = new AcmeProperties();
    private DeploymentProperties deployment = new DeploymentProperties();
    private DigiCertProperties   digicert   = new DigiCertProperties();
    private GlobalSignProperties globalsign = new GlobalSignProperties();
    private EjbcaProperties      ejbca      = new EjbcaProperties();
    private SmallstepProperties  smallstep  = new SmallstepProperties();
    private ScepProperties       scep       = new ScepProperties();
    private HealthProperties     health     = new HealthProperties();

    /**
     * How the agent talks to the CertPing server: outbound HTTPS to the server's agent gateway with
     * an agent token. Works through NAT, firewalls and HTTPS proxies, and needs no inbound port.
     */
    @Data
    public static class TransportProperties {
        /** Base URL of the CertPing server, for example https://certping.example.com. */
        private String serverUrl;
        /** Agent token (cpa_...) created under Organization & Access, Organization tab, Agents card, Add agent. */
        private String token;
        /** How long one receive call waits on the server for work. */
        private Duration pollWait = Duration.ofSeconds(20);
        /** Timeout for a single gateway request, on top of the poll wait. */
        private Duration requestTimeout = Duration.ofSeconds(30);
        /** Commands handled at the same time, one gateway poller each. */
        private int maxConcurrentJobs = 8;
        /** How long the lock on a command is kept renewed while the agent works on it. */
        private Duration maxLockRenewal = Duration.ofMinutes(30);
    }

    /**
     * Scheduled-retry policy knobs. Bound from {@code agent.retry.*}. Spring's relaxed binding
     * accepts duration shorthand (e.g. {@code 48h}, {@code 30s}) for the {@link Duration} fields
     * and a comma-separated list for {@link #blindBackoff} (e.g. {@code 30s,2m,10m,1h,6h,12h,24h}).
     */
    @Data
    public static class RetryProperties {
        /** Scheduled retries allowed before the listener gives up and dead-letters (RETRY_GIVE_UP). */
        private int maxScheduledRetries = 8;
        /**
         * Retries allowed per retry reason, counted for that reason alone, in place of
         * {@link #maxScheduledRetries}. A negative value sets no count, for a reason whose caller bounds its own
         * retries; {@link #absoluteMaxScheduledRetries} still applies.
         */
        private Map<String, Integer> maxRetriesByReason = new LinkedHashMap<>(Map.of(
                "CA_ORDER_PENDING", -1, "DNS_PROPAGATION_PENDING", 3, "RESPONSE_PUBLISH_FAILED", -1));
        /** Scheduled retries of any reasons after which a message is always dead-lettered. */
        private int absoluteMaxScheduledRetries = 200;
        /** Cap on a single honored {@code Retry-After} for new-order flows. */
        private Duration hardCapNewOrder = Duration.ofHours(48);
        /** Cap on a single honored {@code Retry-After} for renewal flows (existing cert still valid). */
        private Duration hardCapRenewal = Duration.ofHours(168);
        /**
         * How long after its original enqueue time a new-order message may still be retried. The server waits
         * this out, plus a margin, before it treats the attempt as lost; the full blind backoff curve stays inside it.
         */
        private Duration maxAttemptAgeNewOrder = Duration.ofHours(96);
        /** As {@link #maxAttemptAgeNewOrder}, for renewals; equal to the server's {@code CERT_RENEWAL} time to live. */
        private Duration maxAttemptAgeRenewal = Duration.ofHours(168);
        /** Upward jitter ceiling (percent) added to every scheduled delay to avoid thundering herds. */
        private int jitterPercent = 10;
        /** Blind backoff curve, indexed by {@code RetryCount}; the last entry is reused once exhausted. */
        private List<Duration> blindBackoff = List.of(
                Duration.ofSeconds(30),
                Duration.ofMinutes(2),
                Duration.ofMinutes(10),
                Duration.ofHours(1),
                Duration.ofHours(6),
                Duration.ofHours(12),
                Duration.ofHours(24));
    }

    @Data
    public static class KeyVaultProperties {
        private String uri;
        private boolean disableChallengeResourceVerification = false;
    }

    @Data
    public static class AcmeProperties {
        private String                    directoryUrl;
        /**
         * Contact address registered on new ACME accounts; {@code {organizationId}} is replaced.
         * Blank registers the account without a contact.
         */
        private String                    accountContact = "";
        /**
         * External account binding (RFC 8555 section 7.3.4), for CAs that only register accounts their
         * customers bound, such as ZeroSSL, Google Trust Services and SSL.com: the key id and the
         * base64url HMAC key the CA issued. Used only when a new account is registered; blank means none.
         */
        private String                    eabKeyId;
        @lombok.ToString.Exclude
        private String                    eabHmacKey;
        private int                       maxRateLimitRetries = 3;
        private ChallengeProperties       challenge        = new ChallengeProperties();
        private DnsVerificationProperties dnsVerification = new DnsVerificationProperties();
        /** The wait for TXT records the agent published itself; {@code dnsVerification} is the manual check. */
        private DnsVerificationProperties automatedDnsVerification = new DnsVerificationProperties();
    }

    @Data
    public static class ChallengeProperties {
        private long dnsPropagationWaitMs;
        private int  maxAttempts;
        private long pollIntervalMs;
        private long orderTimeoutMs;
    }

    @Data
    public static class DnsVerificationProperties {
        private int  maxAttempts;
        private long pollIntervalMs;
    }

    @Data
    public static class DeploymentProperties {
        private AwsProperties aws = new AwsProperties();
    }

    @Data
    public static class AwsProperties {
        private int    sessionDurationSeconds = 3600;
        private String sessionName = "certping-agent";
    }

    @Data
    public static class DigiCertProperties {
        private String apiBaseUrl;
        /** In-process polling, used only when the order cannot be collected later (an external CSR). */
        private long   orderPollIntervalMs;
        private int    orderPollMaxAttempts;
        /** How often a placed order is collected, see {@link com.certping.agent.ssl.CaOrderPolling}. */
        private List<Duration> orderPollIntervals = List.of(Duration.ofSeconds(15), Duration.ofSeconds(30),
                Duration.ofSeconds(60));
        /** How long after it was placed an order may still be pending before it is given up. */
        private Duration orderDeadline = Duration.ofMinutes(5);
    }

    @Data
    public static class GlobalSignProperties {
        private String apiBaseUrl;
        private String loginPath = "/login";
        private String issuePath = "/certificates";
        private String trustChainPath = "/trustchain";
        private String apiKey;
        private String apiSecret;
        private String clientCertPemBase64;
        private String clientPrivateKeyPemBase64;
        private long pollIntervalMs = 10000;
        private int pollMaxAttempts = 30;
        private long tokenTtlSeconds = 600;

        // One JSON string per policy section — parsed at runtime and merged with policy constraints.
        // Example: AGENT_GLOBALSIGN_SUBJECT_DN_JSON={"organization":"Acme","country":"US"}
        private String subjectDnJson;
        private String sanJson;
        private String keyUsagesJson;
        private String extendedKeyUsagesJson;
        private String subjectDaJson;
        private String qualifiedStatementsJson;
        private String msExtensionTemplateJson;
        private String customExtensionsJson;
        private String signatureJson;

        /** When true, fail fast if policy requires fields the agent does not support yet. */
        private boolean strictPolicyValidation = true;
    }

    /**
     * EJBCA connector config. Unlike DigiCert (per-tenant KV handle in the inbound message),
     * EJBCA is configured per agent deployment: the endpoint only exists inside the
     * customer's network and signing is synchronous, so there is no room for a
     * credential-lookup round trip in the enrollment path.
     *
     * <p>Deliberately absent: {@code edition} and {@code version}. Both auth methods are
     * identical on Community and Enterprise across every supported release, and
     * {@code GET /v1/certificate/status} reports both unauthenticated at runtime — a stored
     * copy would only go stale when the customer upgrades.
     */
    @Data
    public static class EjbcaProperties {
        /** Master switch. When false the driver never touches the secret store. */
        private boolean enabled = false;
        /**
         * Handle to the credential JSON in the customer's secret manager, in whatever format
         * the configured {@code SecretStore} driver understands (Azure KV secret URI,
         * AWS Secrets Manager ARN, or GCP resource name).
         */
        private String credentialPath;
        /**
         * The credential JSON itself, for deployments that inject it directly as an env var
         * (mirrors {@code agent.device-sources.profiles[].credentials-json}) instead of a
         * secret-store handle. Takes precedence over {@link #credentialPath} when both are set.
         */
        private String credentialsJson;
        /** Overrides {@code baseUrl} inside the secret when an operator wants it in the manifest. */
        private String baseUrl;

        // Non-secret enrollment parameters. pkcs10enroll rejects a request that omits any of
        // these three, and there is no safe default — they depend on how the customer
        // configured their CA, so startup fails fast when enabled and any is blank.
        private String caName;
        private String certificateProfileName;
        private String endEntityProfileName;

        /**
         * Which CSR field supplies the EJBCA end entity name when the caller does not pass an
         * explicit device id: {@code cn}, {@code dns}, {@code uri} or {@code ip}. Blank means
         * try each in that order. Mirrors Keyfactor's own cert-manager issuer.
         */
        private String endEntityNameSource;
        /**
         * Optional prefix for the end entity name, e.g. {@code acme-corp-}. Use when one EJBCA
         * instance serves multiple tenants and device CNs are not globally unique — without it
         * two devices sharing a CN collapse onto one end entity.
         */
        private String endEntityNamePrefix;

        private int requestTimeoutSeconds = 30;
    }

    /** Smallstep step-ca connector. JWK signing works in open-source and commercial deployments. */
    @Data
    public static class SmallstepProperties {
        private boolean enabled = false;
        /** Secret-store handle for the JWK provisioner credential JSON. */
        private String credentialPath;
        /**
         * The JWK provisioner credential JSON itself, for deployments that inject it directly as
         * an env var instead of a secret-store handle. Takes precedence over
         * {@link #credentialPath} when both are set.
         */
        private String credentialsJson;
        /** Optional non-secret override for the authority URL in the credential. */
        private String baseUrl;
        private int requestTimeoutSeconds = 30;
        /** Hard response-size limit for the signed CRL fetched from step-ca. */
        private int maxCrlBytes = 16 * 1024 * 1024;
        /** Per-pod limit for concurrent bounded CRL downloads and signature checks. */
        private int maxConcurrentCrlFetches = 4;
    }

    /**
     * SCEP device-enrollment endpoint (RFC 8894). When enabled the agent exposes
     * {@code /scep/v1/{endpointId}} and signs enrolled CSRs through the configured CA backend
     * (default: the EJBCA driver). Off by default — existing SSL-only deployments are unaffected.
     */
    @Data
    public static class ScepProperties {
        /** Master switch. When false no SCEP bean is created and the endpoint does not exist. */
        private boolean enabled = false;
        /**
         * Public base URL of this agent's SCEP listener (scheme + host, no path), advertised to
         * Intune certificate profiles as {@code <publicBaseUrl>/scep/v1/<connectionProfileRef>}.
         * Endpoint IDs come from the configured device-source {@code profile-ref} values, never
         * from a static setting — one URL per Intune connection, not per certificate profile.
         */
        private String publicBaseUrl;
        /**
         * Also serve {@code /scep/v1/default} when exactly one eligible Intune source exists, for
         * SCEP profiles created before source-scoped routing. Never created with several sources —
         * that would require guessing which tenant credential validates a challenge.
         */
        private boolean defaultCompatibilityAlias = true;
        /** GetCACaps advertisement. Only strong, actually-supported capabilities (RFC 8894 §2.9). */
        private List<String> caps = List.of(
                "SCEPStandard", "POSTPKIOperation", "SHA-256", "SHA-512", "AES", "Renewal");
        /** Retry-dedup window for {@code (endpointId, transactionID)} in the transaction store. */
        private Duration txnStateTtl = Duration.ofMinutes(15);
        private IntuneScepProperties intune = new IntuneScepProperties();
        private ScepCaProperties     ca     = new ScepCaProperties();
    }

    @Data
    public static class IntuneScepProperties {
        /** Must be enabled whenever the SCEP endpoint is enabled. */
        private boolean enabled = false;
        /**
         * Tenant credentials are not configured here: the validator resolves them per SCEP source
         * route from {@code agent.device-sources.profiles[].credentials-json}, so each Intune
         * connection validates against its own tenant.
         */
        private String providerNameAndVersion = "CertPing-Agent/0.1";
    }

    @Data
    public static class ScepCaProperties {
        /** Production SCEP issuer: {@code ejbca} or {@code smallstep}. */
        private String backend = "ejbca";
        /** SecretStore handle for the RA PKCS#12 JSON {@code {"p12":"<base64>","password":"..."}}. */
        private String raKeystoreHandle;
    }

    @Data
    public static class HealthProperties {
        private long heartbeatIntervalMs = 300_000L;
        private long schedulerTickMs = 5_000L;
        /** Delay before the first CA health report, so probes run after the context settles. */
        private long caReportInitialDelayMs = 30_000L;
        /** Cadence of {@code AGENT_CA_HEALTH_REPORT}. Slower than the heartbeat: it costs a
         *  network round trip per connector and CA state changes rarely. */
        private long caReportIntervalMs = 300_000L;
    }
}
