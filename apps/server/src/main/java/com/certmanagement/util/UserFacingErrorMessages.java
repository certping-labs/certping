// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import java.util.Locale;

/**
 * Maps internal/agent error codes to clean, user-facing messages.
 *
 * <p>The raw {@code errorDetail} produced by {@code certping-agent} (and other internal
 * components) frequently contains diagnostic noise, stack fragments, provider-specific wording,
 * and other system details that must never reach the end user. This mapper is the single place
 * that translates a (machine) error code into a short, actionable sentence.
 *
 * <p>The agent's code set is <b>open</b> (free-form strings over the message queue), so the mapping runs in
 * four layers, most specific first:
 *
 * <ol>
 *   <li><b>Bespoke</b> — codes whose cause implies one concrete fix get copy written for them.</li>
 *   <li><b>Behaviour families</b> — cross-cutting outcomes that mean the same thing wherever they
 *       occur (throttling, quota, credentials, timeout, …).</li>
 *   <li><b>Subsystem</b> — a code we have no specific copy for still names <em>which system</em>
 *       failed, derived from its prefix. Saying "your EJBCA certificate authority" beats "the
 *       provider" even when we cannot say more.</li>
 *   <li><b>Generic</b> — only a code matching none of the above, which should be rare.</li>
 * </ol>
 *
 * <p>Three rules govern the copy itself:
 *
 * <ul>
 *   <li>Never emit error codes, identifiers, hostnames or raw exception text. Callers keep the raw
 *       {@code errorDetail} / {@code errorCode} for logs, alerts and audit.</li>
 *   <li>Never tell the user to retry a failure that cannot succeed on retry. A permanent
 *       misconfiguration needs a fix, not another attempt.</li>
 *   <li>Point at the party who can actually act. A failure inside CertPing itself
 *       must not be described as the customer's provider failing.</li>
 * </ul>
 */
public final class UserFacingErrorMessages {

    private static final String GENERIC =
            "The operation could not be completed. Please try again, or ask your CertPing administrator if the problem persists.";

    /**
     * Failures caused by a defect on our side. The user cannot fix these and must not be sent
     * round a retry loop; the reference id shown alongside is what support needs.
     */
    private static final String INTERNAL =
            "Something went wrong on the server while processing this request. "
                    + "Share the reference id shown below with your CertPing administrator; the server log has the details.";

    private UserFacingErrorMessages() {
    }

    /**
     * Resolves a user-facing message, unwrapping the {@code RETRY_GIVE_UP} wrapper when the
     * underlying classifier code ({@code lastReason}) is known so more specific guidance is shown.
     *
     * @param errorCode  the stored/terminal error code (may be {@code null})
     * @param lastReason the inner classifier code when {@code errorCode} is {@code RETRY_GIVE_UP}
     *                   (may be {@code null})
     */
    public static String forCode(String errorCode, String lastReason) {
        return forCode(resolveCode(errorCode, lastReason));
    }

    /**
     * Resolves the most specific classifier code, unwrapping the {@code RETRY_GIVE_UP} wrapper to
     * its inner {@code lastReason} when present. Components persisting a terminal error code should
     * store <em>this</em> value so the later user-facing message reflects the real cause rather than
     * the opaque retry wrapper.
     *
     * @param errorCode  the terminal/stored error code (may be {@code null})
     * @param lastReason the inner classifier when {@code errorCode} is {@code RETRY_GIVE_UP}
     *                   (may be {@code null})
     * @return the unwrapped inner code when applicable, otherwise {@code errorCode} unchanged
     */
    public static String resolveCode(String errorCode, String lastReason) {
        boolean isRetryWrapper = "RETRY_GIVE_UP".equals(errorCode)
                && lastReason != null && !lastReason.isBlank();
        return isRetryWrapper ? lastReason : errorCode;
    }

    /**
     * Resolves a user-facing message for a single error code. Unknown or {@code null} codes fall
     * back to a generic message that exposes no internal detail.
     */
    public static String forCode(String errorCode) {
        if (errorCode == null || errorCode.isBlank()) {
            return GENERIC;
        }
        String code = errorCode.trim().toUpperCase(Locale.ROOT);

        String message = bespoke(code);
        if (message == null) {
            message = behaviourFamily(code);
        }
        if (message == null) {
            message = subsystem(code);
        }
        return message == null ? GENERIC : message;
    }

    // ---------------------------------------------------------------------
    // Layer 1 — bespoke copy for codes with one concrete cause and one fix.
    // ---------------------------------------------------------------------

    private static String bespoke(String code) {
        switch (code) {
            // -- Retry wrapper with no inner reason -----------------------------------------
            case "RETRY_GIVE_UP":
                return "We tried this several times and couldn't complete it. Please re-trigger the request, "
                        + "and ask your CertPing administrator if it keeps failing.";

            // -- Agent result ---------------------------------------------------------------
            case "ISSUED_WITHOUT_EXPIRY":
                return "The certificate authority's answer was incomplete, so this certificate was not activated. "
                        + "Please request it again, and ask your CertPing administrator if it repeats.";

            // -- Domain validation ----------------------------------------------------------
            case "ACME_RATE_LIMITED":
                return "Let's Encrypt rate-limited this certificate. Please try again later.";
            case "ACME_CHALLENGE_INVALID":
                return "Domain validation failed. Verify your DNS configuration and the _acme-challenge TXT "
                        + "record, then try again.";
            case "ACME_ORDER_INVALID":
                return "Let's Encrypt rejected the request for this domain. Check that the domain is spelled "
                        + "correctly, is publicly resolvable, and is allowed to be issued for.";
            case "ACME_NO_AUTHORIZATIONS":
                return "Let's Encrypt returned no validation records for this domain, so issuance can't "
                        + "continue. Please start the request again, and ask your CertPing administrator if it repeats.";
            case "ACME_ACCOUNT_CREATE_FAILED":
            case "ACME_ACCOUNT_LOAD_FAILED":
                return "We couldn't set up the Let's Encrypt account used to issue this certificate. "
                        + "Please retry, and ask your CertPing administrator if it persists.";

            // -- DNS ------------------------------------------------------------------------
            case "DNS_NS_LOOKUP_FAILED":
                return "This domain has no working nameservers, so it can't be validated. Check that the "
                        + "registration is still active and that its nameservers are set correctly.";
            case "DNS_ZONE_NOT_FOUND":
                return "This domain's DNS zone wasn't found in the connected DNS account. Confirm the zone "
                        + "exists there and that the credential has access to it.";
            case "DNS_ZONE_NOT_SERVICEABLE":
                return "The connected DNS account can't manage records for this domain. Point the domain at "
                        + "that provider, or attach a credential for the provider that hosts the zone.";
            case "DNS_PROVIDER_UNKNOWN":
                return "We couldn't match this domain to a supported DNS provider. Check the DNS "
                        + "credential attached to this certificate, or issue in manual mode.";
            case "DNS_PROPAGATION_TIMEOUT":
                return "The validation record was created but never became visible in public DNS. This usually "
                        + "means the zone is served by different nameservers than the connected account.";

            // -- Certificate request ---------------------------------------------------------
            case "CSR_KEYTYPE_UNSUPPORTED":
                return "The selected key type isn't supported by this certificate authority. "
                        + "Choose a different key type and try again.";
            case "CSR_EC_KEYSIZE_UNSUPPORTED":
                return "The selected elliptic-curve key size isn't supported by this certificate authority. "
                        + "Choose a supported curve and try again.";

            // -- Certificate authority selection ---------------------------------------------
            case "CA_PRODUCT_NOT_AVAILABLE":
                return "This certificate authority doesn't have the requested product enabled on the configured "
                        + "account. Ask an administrator to update the CA credential so it points at a product SKU "
                        + "your account has access to, then retry.";
            case "CA_ORDER_REJECTED":
                return "The certificate authority rejected this request. Check the domain and certificate "
                        + "options against what your CA account permits.";
            case "MISSING_CA_CREDENTIAL":
                return "No credential is configured for this certificate authority. Add one under "
                        + "Credentials, then retry.";
            case "UNSUPPORTED_CA":
            case "UNKNOWN_CA_PROVIDER":
                return "This certificate authority isn't supported for this operation. Choose a different CA.";
            case "UNSUPPORTED_CA_FOR_MANUAL":
                return "This certificate authority doesn't support manual issuance. Use automated issuance, "
                        + "or choose a different CA.";

            // -- Certificate authority integrations -------------------------------------------
            case "EJBCA_DISABLED":
            case "EJBCA_REST_DISABLED":
                return "The REST API is disabled on your EJBCA server. Enable it, then retry.";
            case "GLOBALSIGN_DOMAIN_INVALID":
            case "GLOBALSIGN_DOMAIN_VERIFICATION_FAILED":
                return "GlobalSign hasn't verified this domain on your account. Complete domain verification "
                        + "with GlobalSign, then retry.";

            // -- Secret store -------------------------------------------------------------------
            // KV_* is Azure Key Vault; SM_* is AWS Secrets Manager or GCP Secret Manager. Only the
            // KV codes may say "key vault" — the rest use the product-neutral "secret store".
            case "KV_ACCESS_DENIED":
                return "Access to your key vault was denied. Check that CertPing still has read access "
                        + "to the vault holding this credential, then retry.";
            case "SM_ACCESS_DENIED":
                return "Access to your secret store was denied. Check that CertPing still has read access "
                        + "to the secret holding this credential, then retry.";
            case "KV_URI_BLANK":
            case "KV_URI_INVALID":
                return "The key vault location saved on this credential is missing or malformed. "
                        + "Re-save the credential under Credentials, then retry.";
            case "SM_HANDLE_BLANK":
                return "The secret store location saved on this credential is missing. "
                        + "Re-save the credential under Credentials, then retry.";
            case "SM_HANDLE_INVALID":
                return "The agent that ran this job cannot read the secret store this credential is kept in. "
                        + "A secret pasted into CertPing is readable only by agents using the server's store "
                        + "(for the LOCAL store, the bundled agent). Store the secret in this agent's vault, "
                        + "re-save the credential with its address, then retry.";

            // -- Deployment -------------------------------------------------------------------
            case "DEPLOY_AUTH_INVALID":
                return "Your cloud provider credentials were rejected. Please update them under Integrations, "
                        + "then retry.";
            case "DEPLOY_AZURE_PERMISSION_DENIED":
                return "An Azure identity used by this deployment is missing a permission it needs. "
                        + "The CertPing agent log names the denied action and resource; grant the role listed "
                        + "for this target in the deployment target docs, then retry.";
            case "DEPLOY_AZURE_CLIENT_ID_MISSING":
                return "The Azure credential has no Client ID. Add the Client ID of the app registration or "
                        + "managed identity to the credential under Integrations, then retry.";
            case "DEPLOY_KEY_ENCRYPTED":
                return "The private key for this certificate is passphrase-protected, which this deployment "
                        + "target doesn't accept. Re-issue without a passphrase, then deploy again.";
            case "DEPLOY_CLOUDFRONT_DEFAULT_CERT":
                return "This CloudFront distribution uses the default CloudFront certificate. Add your domain "
                        + "as an alternate domain name on the distribution before deploying a certificate to it.";
            case "DEPLOY_CLOUDFRONT_IAM_CERT":
                return "This CloudFront distribution uses a certificate stored in IAM, which we can't replace. "
                        + "Switch the distribution to an ACM certificate, then deploy again.";

            // -- Revocation --------------------------------------------------------------------
            case "REVOCATION_UNAUTHORIZED":
                return "The certificate authority wouldn't allow this certificate to be revoked with the "
                        + "configured credential. Check that the credential owns this certificate.";
            case "REVOCATION_INVALID_STATE":
                return "This certificate isn't in a state that can be revoked.";

            // -- Machine identity ----------------------------------------------------------------
            case "PLATFORM_NOT_CONFIGURED":
                return "This device source isn't fully configured yet. Finish setting it up under Connectors, "
                        + "then retry.";
            case "PLATFORM_NOT_SUPPORTED":
                return "This operation isn't supported for this type of device source.";
            case "SCEP_ENDPOINT_NOT_CONFIGURED":
            case "SCEP_ENDPOINT_INVALID":
                return "The SCEP endpoint for this device source is missing or invalid. Check the connector "
                        + "settings, then retry.";

            // -- Defects on our side -------------------------------------------------------------
            case "UNKNOWN_MESSAGE_TYPE":
            case "MISSING_ORGANIZATION_ID":
            case "ORGANIZATION_ID_MISSING":
            case "ACME_ACCOUNT_PATH_MISSING":
            case "ACME_ORDER_URL_MISSING":
            case "MISSING_ORDER_ID":
            case "DEPLOY_RESULT_NULL_ARN":
            case "DEPLOY_RESULT_NULL_RESOURCE_ID":
            case "DNS_TXT_REQUESTS_EMPTY":
            case "DNS_VERIFICATION_EMPTY":
            case "INVALID_SYNC_COMMAND":
            case "INVALID_SYNC_MODE":
            case "INVALID_PROFILE_COMMAND":
            case "INVALID_PROFILE_SYNC_COMMAND":
            case "PROFILE_SYNC_SERIALIZATION_FAILED":
            case "PROFILE_RESPONSE_DELIVERY_FAILED":
            case "SERIALIZATION_FAILED":
            case "SEND_FAILED":
            case "STAGED_KEY_CORRUPT":
                return INTERNAL;

            // -- Manual issuance ------------------------------------------------------------------
            case "MANUAL_TXT_REQUEST_INVALID":
                return "This manual validation request is no longer valid. Start the manual issuance flow "
                        + "again to get a fresh TXT record.";

            default:
                return null;
        }
    }

    // ---------------------------------------------------------------------
    // Layer 2 — outcomes that mean the same thing wherever they occur.
    // ---------------------------------------------------------------------

    private static String behaviourFamily(String code) {
        // Provider rate-limiting / throttling.
        if (code.contains("THROTTLED") || code.contains("RATE_LIMITED")) {
            if (code.startsWith("CA_") || code.startsWith("ACME")) {
                return "The certificate authority is temporarily rate-limiting requests. "
                        + "This usually clears on its own, so please try again shortly.";
            }
            if (code.startsWith("DNS")) {
                return "Your DNS provider is temporarily rate-limiting requests. "
                        + "This usually clears on its own, so please try again shortly.";
            }
            if (code.startsWith("KV_")) {
                return "Your key vault is temporarily rate-limiting requests. "
                        + "This usually clears on its own, so please try again shortly.";
            }
            if (code.startsWith("SM_")) {
                return "Your secret store is temporarily rate-limiting requests. "
                        + "This usually clears on its own, so please try again shortly.";
            }
            return "Your cloud provider is temporarily rate-limiting requests. "
                    + "This usually clears on its own, so please try again shortly.";
        }

        // Provider resource quota exhausted (e.g. GCP compute SSL-certificates per-project limit).
        if (code.contains("QUOTA") || code.contains("RESOURCE_EXHAUSTED")
                || code.contains("BUDGET_EXCEEDED")) {
            return "Your cloud project has reached a resource quota, such as the maximum number "
                    + "of SSL certificates allowed per project. Remove unused resources or request a "
                    + "quota increase from your cloud provider, then retry.";
        }

        // Domain validation / ACME challenge.
        if (code.contains("CHALLENGE")) {
            return "Domain validation failed. Check your DNS configuration and the _acme-challenge TXT record, "
                    + "then try again.";
        }

        // Credentials / authorization rejected or missing. Where the credential lives differs by
        // subsystem, so the guidance names the screen that actually holds it.
        if (code.contains("CREDENTIAL_INVALID") || code.contains("AUTH_INVALID")
                || code.contains("ACCESS_DENIED") || code.endsWith("_DENIED")
                || code.contains("AUTH_FAILED") || code.contains("CRED_MISSING")
                || code.contains("CREDENTIAL_MISSING")
                || code.contains("OAUTH_REJECTED") || code.contains("CREDENTIAL_NOT_PRESENTED")) {
            boolean absent = code.contains("MISSING") || code.contains("NOT_PRESENTED");
            if (code.startsWith("DNS")) {
                return absent
                        ? "No usable DNS credential is attached to this certificate. Attach one under "
                                + "Credentials, then retry."
                        : "Your DNS provider rejected the credential for this domain. Update it under "
                                + "Credentials, then retry.";
            }
            if (isCertificateAuthority(code)) {
                String screen = caCredentialScreen(code);
                return absent
                        ? "No credential is configured for this certificate authority. Add one under "
                                + screen + ", then retry."
                        : "Your certificate authority rejected the configured credential. Update the CA "
                                + "credential under " + screen + ", then retry.";
            }
            if (isDeviceSource(code)) {
                return absent
                        ? "No credential is configured for this device source. Add one under Connectors, "
                                + "then retry."
                        : "This device source rejected the configured credential, or it no longer has the "
                                + "permissions we need. Review it under Connectors, then retry.";
            }
            return absent
                    ? "The credentials for this provider are missing. Please add them under Integrations, "
                            + "then retry."
                    : "Your provider credentials were rejected. Please re-check and update them under "
                            + "Integrations, then retry.";
        }

        // Certificate rejected / format problem.
        if (code.contains("CERT_REJECTED") || code.contains("CERT_INVALID")
                || code.contains("CERT_FORMAT_INVALID") || code.contains("PFX_BUILD_FAILED")
                || code.startsWith("KEY_PAIR_")) {
            return "The certificate was rejected by the provider, usually because of a format or compatibility issue. "
                    + "Please retry, or ask your CertPing administrator if it persists.";
        }

        // Configuration invalid, incomplete, or missing. Where that configuration lives
        // differs by subsystem, so an unrecognised owner falls through to the subsystem
        // layer rather than being described as a deployment problem.
        if (code.contains("CONFIG_INVALID") || code.contains("CONFIG_MISSING")
                || code.contains("CONFIGURATION_INVALID") || code.contains("TARGETS_INVALID")
                || code.contains("URI_INVALID") || code.endsWith("_MISSING")
                || code.endsWith("_REQUIRED")) {
            if (isCertificateAuthority(code)) {
                return "A required setting is missing from your certificate authority configuration. "
                        + "Review the CA credential and its settings under " + caCredentialScreen(code)
                        + ", then retry.";
            }
            if (code.startsWith("DEPLOY_") || code.startsWith("DEPLOYMENT")) {
                return "Your deployment configuration is invalid or incomplete. "
                        + "Please review the target settings and try again.";
            }
            if (code.startsWith("DNS_")) {
                return "The DNS settings for this certificate are incomplete. "
                        + "Check the DNS credential attached to it, then retry.";
            }
            if (code.startsWith("PLATFORM_") || code.startsWith("SCEP_") || code.startsWith("PROFILE_")) {
                return "This device source isn't fully configured. Finish setting it up under Connectors, "
                        + "then retry.";
            }
        }

        // Referenced resource not found.
        if (code.contains("NOT_FOUND")) {
            return "A resource referenced in your configuration wasn't found. "
                    + "Please confirm it exists and the name is correct.";
        }

        // Conflicting resource.
        if (code.contains("CONFLICT")) {
            return "A conflicting resource already exists and may need manual cleanup before this can succeed.";
        }

        // Timed out.
        if (code.contains("TIMEOUT")) {
            return "The operation timed out. The provider may be slow right now, so please try again.";
        }

        return null;
    }

    // ---------------------------------------------------------------------
    // Layer 3 — name the system that failed, even without specific copy.
    // ---------------------------------------------------------------------

    private static String subsystem(String code) {
        // Certificate authorities.
        if (isCertificateAuthority(code)) {
            return "Your certificate authority (" + caName(code) + ") couldn't complete this request. "
                    + "Check that it's reachable and that your account there is in good standing.";
        }

        // Domain validation over DNS.
        if (code.startsWith("DNS_")) {
            return "We couldn't complete DNS validation for this domain through the connected DNS account. "
                    + "Check the zone and the credential attached to this certificate.";
        }

        // Secret stores holding the customer's own credentials — their Azure Key Vault, AWS
        // Secrets Manager or GCP Secret Manager. Not CertPing's own store, and only the
        // Azure codes may be called a key vault.
        if (code.startsWith("KV_")) {
            return "We couldn't read the credential for this request from your key vault. "
                    + "Check that the vault is reachable and that the access granted to CertPing is "
                    + "still in place, then retry.";
        }
        if (code.startsWith("SM_") || code.startsWith("SECRET_")) {
            return "We couldn't read the credential for this request from your secret store. "
                    + "Check that it's reachable and that the access granted to CertPing is "
                    + "still in place, then retry.";
        }

        // Deployment to a customer-owned target.
        if (code.startsWith("DEPLOY_") || code.equals("DEPLOYMENT_FAILED")) {
            String target = deploymentTarget(code);
            return target == null
                    ? "We couldn't deploy the certificate to the configured target. "
                            + "Check the target settings and its credentials, then retry."
                    : "We couldn't deploy the certificate to " + target + ". "
                            + "Check the target settings and its credentials, then retry.";
        }

        // Certificate discovery.
        if (code.startsWith("DISCOVERY_")) {
            return "We couldn't finish scanning this environment for certificates. "
                    + "Check the scan target and its credentials, then run discovery again.";
        }

        // Device sources, certificate profiles and device sync.
        if (code.startsWith("PROFILE_")) {
            return "We couldn't apply this certificate profile to the device source. "
                    + "Check the profile settings, then retry.";
        }
        if (code.startsWith("SYNC_") || code.startsWith("PLATFORM_")) {
            return "We couldn't sync with this device source. Check the connector settings and its "
                    + "credentials, then retry.";
        }
        if (code.startsWith("SCEP_")) {
            return "The SCEP endpoint for this device source couldn't be used. "
                    + "Check the connector settings, then retry.";
        }

        // Certificate lifecycle steps that failed before reaching an external system.
        if (code.startsWith("CSR_")) {
            return "We couldn't build the certificate request from the options you selected. "
                    + "Review the key type and subject details, then try again.";
        }
        if (code.startsWith("REVOCATION_")) {
            return "The certificate authority couldn't revoke this certificate. "
                    + "Please retry, and ask your CertPing administrator if it persists.";
        }
        if (code.startsWith("ACME_")) {
            return "Let's Encrypt couldn't complete this request. "
                    + "This often clears on its own, so please try again shortly.";
        }
        if (code.startsWith("ISSUANCE_") || code.startsWith("RENEWAL_") || code.startsWith("CERT_")) {
            return "We couldn't complete this certificate operation. "
                    + "Please retry, and ask your CertPing administrator if it persists.";
        }

        return null;
    }

    // ---------------------------------------------------------------------
    // Helpers.
    // ---------------------------------------------------------------------

    /** True for codes raised by a certificate-authority integration rather than a deployment target. */
    private static boolean isCertificateAuthority(String code) {
        return code.startsWith("CA_")
                || code.startsWith("EJBCA_")
                || code.startsWith("GLOBALSIGN_")
                || code.startsWith("SMALLSTEP_")
                || code.startsWith("DIGICERT_")
                || code.startsWith("AKAMAI_");
    }

    /** True for CA integrations configured as machine-identity connectors. */
    private static boolean isConnectorCertificateAuthority(String code) {
        return code.startsWith("EJBCA_")
                || code.startsWith("GLOBALSIGN_")
                || code.startsWith("SMALLSTEP_");
    }

    /** Screen on which the credential for this CA is managed. */
    private static String caCredentialScreen(String code) {
        return isConnectorCertificateAuthority(code) ? "Connectors" : "Credentials";
    }

    /** True for codes raised while talking to a device source (Intune, SCEP, profiles). */
    private static boolean isDeviceSource(String code) {
        return code.startsWith("PLATFORM_")
                || code.startsWith("INTUNE_")
                || code.startsWith("SCEP_")
                || code.startsWith("PROFILE_")
                || code.startsWith("SYNC_");
    }

    /** Display name for the CA behind a code. Never returns a raw code fragment. */
    private static String caName(String code) {
        if (code.startsWith("EJBCA_")) {
            return "EJBCA";
        }
        if (code.startsWith("GLOBALSIGN_")) {
            return "GlobalSign";
        }
        if (code.startsWith("SMALLSTEP_")) {
            return "Smallstep";
        }
        if (code.startsWith("DIGICERT_")) {
            return "DigiCert";
        }
        if (code.startsWith("AKAMAI_")) {
            return "Akamai CPS";
        }
        return "the configured CA";
    }

    /**
     * Display name for a {@code DEPLOY_<TARGET>_*} code, or {@code null} when the target segment
     * isn't one we recognise — in which case the caller falls back to unnamed wording rather than
     * echoing part of the code.
     */
    private static String deploymentTarget(String code) {
        if (code.startsWith("DEPLOY_ACM_") || code.startsWith("DEPLOY_AWS_")) {
            return "AWS";
        }
        if (code.startsWith("DEPLOY_CLOUDFRONT_")) {
            return "CloudFront";
        }
        if (code.startsWith("DEPLOY_CLOUDFLARE_")) {
            return "Cloudflare";
        }
        if (code.startsWith("DEPLOY_AZURE_")) {
            return "Azure";
        }
        if (code.startsWith("DEPLOY_GCP_")) {
            return "Google Cloud";
        }
        if (code.startsWith("DEPLOY_K8S_")) {
            return "your Kubernetes cluster";
        }
        if (code.startsWith("DEPLOY_F5_")) {
            return "your F5 BIG-IP device";
        }
        if (code.startsWith("DEPLOY_AKAMAI_")) {
            return "Akamai";
        }
        if (code.startsWith("DEPLOY_APIGW_")) {
            return "API Gateway";
        }
        if (code.startsWith("DEPLOY_ELB_")) {
            return "your load balancer";
        }
        if (code.startsWith("DEPLOY_STS_")) {
            return "AWS";
        }
        return null;
    }
}
