// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;

import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Translates EJBCA's HTTP failures into the agent's exception model.
 *
 * <p>Split out from {@link EjbcaClient} because EJBCA's failure modes are distinctive enough to
 * be worth reading as one list. Each branch exists because the operator action differs; a bare
 * status code would not tell them which.
 */
final class EjbcaErrorMapper {

    /** Upstream bodies land in exception messages and therefore in logs; keep them bounded. */
    private static final int MAX_ERROR_BODY_CHARS = 2000;

    private EjbcaErrorMapper() {
    }

    static void assertSuccess(HttpResponse<String> response, String operation) {
        int status = response.statusCode();
        if (status >= 200 && status < 300) {
            return;
        }

        // Truncate before lower-casing so a large error page is never duplicated in memory.
        String body = truncate(response.body() == null ? "" : response.body());
        String lower = body.toLowerCase();

        if (isRedirect(status)) {
            // Redirects are deliberately not followed: EJBCA 302s plain HTTP to 8443, and a
            // redirected POST silently loses its body, which looks like an empty request.
            throw new PermanentAgentException("EJBCA_UNEXPECTED_REDIRECT",
                    operation + " was redirected (" + status + ") to '"
                            + response.headers().firstValue("location").orElse("?")
                            + "'. Check that baseUrl points at the https port.");
        }
        if (status == 429 || status == 503 || status == 408) {
            // A device fleet enrolling at once will trip EJBCA's own limiter or a proxy in front
            // of it. Dead-lettering those loses certificates that would succeed seconds later.
            // Same treatment GlobalSignAtlasClient gives 429/503.
            Duration retryAfter = response.headers().firstValue("retry-after")
                    .flatMap(RateLimitClassifier::parseRetryAfterValueOpt)
                    .orElse(null);
            throw new RetryableAgentException("CA_PROVIDER_THROTTLED",
                    operation + " was throttled by EJBCA (HTTP " + status + ")"
                            + (retryAfter == null ? " (no Retry-After supplied)"
                                                  : " (Retry-After=" + retryAfter + ")")
                            + ": " + body, retryAfter);
        }
        if (status == 403 && isRestDisabled(body)) {
            // REST ships disabled, making this the most common first-run failure. EJBCA signals
            // it with an HTML body, the only non-JSON error it returns.
            throw new PermanentAgentException("EJBCA_REST_DISABLED",
                    "EJBCA REST protocol is disabled. Enable it with: ejbca.sh config protocols "
                            + "enable --name \"REST Certificate Management\". (" + operation + ")");
        }
        if (status == 401 || status == 403) {
            throw authFailure(lower, body, operation, status);
        }
        if (status == 404 && lower.contains("resteasy003210")) {
            throw new PermanentAgentException("EJBCA_ENDPOINT_ABSENT",
                    operation + " is not available on this EJBCA version or edition: " + body);
        }
        if (status == 400) {
            // Certificate- and end-entity-profile violations land here: disallowed key size,
            // missing required DN component, forbidden SAN type. The operator needs EJBCA's own
            // wording to know which, so pass it through rather than summarising.
            throw new PermanentAgentException("EJBCA_REQUEST_REJECTED",
                    operation + " was rejected by EJBCA: " + body);
        }
        if (status >= 500) {
            throw new TransientAgentException("EJBCA_SERVER_ERROR",
                    operation + " failed with " + status + ": " + body);
        }
        throw new PermanentAgentException("EJBCA_API_ERROR",
                operation + " failed with " + status + ": " + body);
    }

    private static PermanentAgentException authFailure(String lower, String body,
                                                       String operation, int status) {
        // Order matters: EJBCA's no-credential message is "no client certificate or OAuth token
        // received for authentication", which contains "oauth". Matching on "oauth" first would
        // misreport a P12 that failed to load as a rejected bearer token.
        if (lower.contains("no client certificate")) {
            return new PermanentAgentException("EJBCA_CREDENTIAL_NOT_PRESENTED",
                    "EJBCA received no credential. The P12 likely failed to load, or authMethod "
                            + "disagrees with the fields in the secret. " + operation + ": " + body);
        }
        if (lower.contains("oauth")) {
            return new PermanentAgentException("EJBCA_OAUTH_REJECTED",
                    "EJBCA rejected the OAuth bearer token — it may be expired, carry an unknown "
                            + "'kid', or its subject may not be a role member configured with "
                            + "OAuth2AuthenticationToken:CLAIM_SUBJECT. " + operation + ": " + body);
        }
        return new PermanentAgentException("EJBCA_AUTH_FAILED",
                operation + " was rejected with " + status + ": " + body);
    }

    private static boolean isRedirect(int status) {
        // 303 included: some proxies emit it when downgrading a POST.
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    /**
     * EJBCA's "service has been disabled" page is HTML carrying that phrase. Matching on the
     * phrase rather than merely "not JSON" keeps an empty-bodied 403, or an intercepting proxy's
     * own HTML 403, from sending the operator to reconfigure a CA setting that was never wrong.
     */
    private static boolean isRestDisabled(String body) {
        String lower = body.toLowerCase();
        return lower.contains("service has been disabled")
                || lower.contains("this service has been disabled");
    }

    private static String truncate(String body) {
        return body.length() <= MAX_ERROR_BODY_CHARS
                ? body
                : body.substring(0, MAX_ERROR_BODY_CHARS) + "... (truncated)";
    }
}
