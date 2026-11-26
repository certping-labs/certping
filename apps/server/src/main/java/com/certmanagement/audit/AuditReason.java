// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.util.UserFacingErrorMessages;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Why something failed, as a stable code: the only form a failure's cause takes in an audit row. The
 * row stores the code; the customer-safe sentence is rendered from it when the row is read, so a
 * wording fix reaches old rows too.
 *
 * <p>A reason is built from a code, never from an exception or its message, so no stack trace, SQL,
 * hostname, vault or secret name can reach the trail. The only way to make one is {@link #of(String)}
 * (or {@link #fromAgent}, which calls it), and it never throws: anything that is not a well-formed code
 * becomes {@link #INTERNAL_ERROR}, so a bad code cannot turn an audited failure into another error.
 *
 * <p>The sentences for the API, sign-in and system codes live here. Every other code (the agent's open
 * set, e.g. {@code DEPLOY_AZURE_KV_IMPORT_FAILED}, {@code DNS_AUTH_FAILED}) is rendered by
 * {@link UserFacingErrorMessages}, which already writes the platform's customer-safe copy for them.
 */
public final class AuditReason {

    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]{1,63}$");

    public static final AuditReason INTERNAL_ERROR = new AuditReason("INTERNAL_ERROR");

    private final String code;

    private static final Map<String, String> MESSAGES = Map.ofEntries(
            // API outcomes, matching GlobalExceptionHandler's responses.
            Map.entry("PERMISSION_DENIED", "You don't have permission to do this."),
            Map.entry("NOT_FOUND", "It no longer exists, or you don't have access to it."),
            Map.entry("INVALID_INPUT", "Some of the details entered weren't valid."),
            Map.entry("CONFLICT", "Someone else changed this at the same time. Reload and try again."),
            Map.entry("DUPLICATE", "Something with the same name or details already exists."),
            Map.entry("FEATURE_DISABLED", "This feature isn't available for your organization."),
            Map.entry("PAYMENT_REQUIRED", "This needs an active plan or a valid payment method."),
            Map.entry("RATE_LIMITED", "There were too many attempts in a short time. Try again later."),
            Map.entry("SERVICE_UNAVAILABLE", "The service was briefly unavailable. Try again in a few minutes."),
            Map.entry("QUERY_TIMEOUT", "This took too long to complete. Narrow the filters and try again."),
            Map.entry("LAST_ORGANIZATION_ADMIN", "An organization must keep at least one administrator."),
            // Legacy hosted-product reasons (domains, plans): no longer produced, kept so stored rows still read.
            Map.entry("ORGANIZATION_HOLDS_DOMAINS", "The organization still holds domains."),
            Map.entry("FEATURE_IN_USE", "The feature still has active records."),
            Map.entry("SUBSCRIPTION_HAS_BILLABLE_ITEMS",
                    "Some certificates would still be charged after the plan ends. Remove them first."),
            Map.entry("PLAN_CANCELLATION_SCHEDULED",
                    "The plan is set to end, so no paid certificates can be added. Keep the plan to add them."),
            Map.entry("EXPORT_TOO_LARGE", "The export has too many rows. Choose a shorter date range."),
            Map.entry("EXPORT_LIMIT", "The export limit for this hour was reached. Try again later."),
            // Sign-in.
            Map.entry("INVALID_CREDENTIALS", "The email or password was incorrect."),
            Map.entry("ACCOUNT_DISABLED", "The account is disabled."),
            Map.entry("SSO_REJECTED", "The identity provider rejected the sign-in."),
            Map.entry("SSO_MISCONFIGURED", "Single sign-on isn't set up correctly for this organization."),
            Map.entry("SSO_MEMBER_NOT_PROVISIONED",
                    "No member account exists for this person, and single sign-on isn't set to create one."),
            Map.entry("ACCOUNT_LOCKED", "The account is locked after too many failed attempts. Try again later."),
            Map.entry("MFA_CODE_INVALID", "The one-time code was incorrect or had expired."),
            Map.entry("ORGANIZATION_SUSPENDED", "The organization is suspended."),
            Map.entry("SIGN_IN_METHOD_NOT_ALLOWED", "This account signs in through its organization's sign-in page."),
            Map.entry("SIGN_IN_CANCELLED", "Sign-in was cancelled."),
            // Credentials and where they are used.
            Map.entry("CREDENTIAL_DETAILS_INVALID", "The credential details entered aren't valid for this provider."),
            Map.entry("CREDENTIAL_IN_USE",
                    "The credential is still used by active certificates. Revoke or reassign them first."),
            Map.entry("CREDENTIAL_TYPE_MISMATCH",
                    "The credential chosen is the wrong kind: DNS validation needs a DNS credential, a deployment"
                            + " target a deployment credential."),
            Map.entry("CREDENTIAL_NOT_ACTIVE", "The credential chosen has been deleted."),
            // Legacy billing reason: no longer produced, kept so stored audit rows still read.
            Map.entry("PAYMENT_FAILED",
                    "The payment didn't go through. Check the card on file, or pay the invoice from the billing page."),
            // Certificate downloads (CertExportException codes; the refusal's outcome as the export answered it).
            Map.entry("CERT_NOT_EXPORTABLE", "This certificate can't be downloaded: it isn't active, has expired, "
                    + "or its private key isn't held by CertPing."),
            Map.entry("CERT_MATERIAL_GONE", "The stored certificate is no longer available. Renew or re-issue it, "
                    + "then download it again."),
            Map.entry("CERT_MATERIAL_MISMATCH", "The stored certificate didn't match its record, so it wasn't "
                    + "downloaded. Ask your CertPing administrator."),
            Map.entry("EXPORT_RATE_LIMITED", "There were too many certificate downloads in a short time. "
                    + "Try again later."),
            Map.entry("EXPORT_KEY_NOT_PERMITTED", "Downloading a private key needs the permission to deploy "
                    + "certificates."),
            Map.entry("EXPORT_UNAVAILABLE", "Certificate downloads were briefly unavailable. Try again in a few "
                    + "minutes."),
            // Notifications and integrations.
            Map.entry("PARTIALLY_DELIVERED",
                    "It reached some of the chosen destinations but not all. Check the integrations that failed."),
            Map.entry("ESCALATION_NOT_DELIVERED",
                    "It couldn't be delivered to any of the chosen destinations. Check the integrations and try again."),
            Map.entry("INTEGRATION_DELIVERY_FAILED",
                    "The integration didn't accept the message. Check that its webhook or credentials are still valid."),
            // Certificate discovery.
            Map.entry("DISCOVERY_FAILED",
                    "The scan didn't finish. Check that the agent is running and its credential can list certificates."),
            Map.entry("DISCOVERY_NOT_PICKED_UP",
                    "No agent picked up the scan in time. Check that the agent is running, then start the scan again."),
            // Device certificate enrollment (SCEP), as the agent reported it.
            Map.entry("CHALLENGE_REJECTED", "The device's enrollment challenge was rejected, so no certificate "
                    + "was issued."),
            Map.entry("CA_REJECTED", "The certificate authority refused the device's request."),
            Map.entry("CA_UNAVAILABLE", "The certificate authority couldn't be reached. The device will retry."),
            Map.entry("INTUNE_UNAVAILABLE", "Microsoft Intune couldn't be reached to check the challenge. "
                    + "The device will retry."),
            Map.entry("ENROLLMENT_FAILED", "The device's enrollment ended without a certificate."),
            // What CertPing skipped on its own.
            Map.entry("FEATURE_OFF", "Skipped because the feature is turned off."),
            Map.entry("CA_NOT_IN_PLAN", "Skipped because the plan doesn't include this certificate authority. "
                    + "Upgrade the plan to renew it."));

    private AuditReason(String code) {
        this.code = code;
    }

    /**
     * The reason for {@code code}, upper-cased and trimmed; {@link #INTERNAL_ERROR} when it is blank or
     * not of the form {@code ^[A-Z][A-Z0-9_]{1,63}$} (so free text can never be stored as a code).
     */
    public static AuditReason of(String code) {
        if (code == null) {
            return INTERNAL_ERROR;
        }
        String normalised = code.trim().toUpperCase(Locale.ROOT);
        return CODE.matcher(normalised).matches() ? new AuditReason(normalised) : INTERNAL_ERROR;
    }

    /**
     * The reason for an agent or provider failure: {@code RETRY_GIVE_UP} is unwrapped to the code that
     * caused it, as the certificate pages store it.
     */
    public static AuditReason fromAgent(String errorCode, String lastReason) {
        return of(UserFacingErrorMessages.resolveCode(errorCode, lastReason));
    }

    /**
     * The sentence a customer reads for this reason. Never contains the code's internals; an internal
     * error names the request id to give the administrator when there is one.
     */
    public String message(String requestId) {
        if (INTERNAL_ERROR.code.equals(code)) {
            return requestId == null || requestId.isBlank()
                    ? "Something went wrong on the server. Ask your CertPing administrator if it keeps happening."
                    : "Something went wrong on the server. Give request ID " + requestId + " to your CertPing administrator.";
        }
        String message = MESSAGES.get(code);
        return message != null ? message : UserFacingErrorMessages.forCode(code);
    }

    /** The stored code. */
    public String code() {
        return code;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof AuditReason reason && code.equals(reason.code);
    }

    @Override
    public int hashCode() {
        return Objects.hash(code);
    }

    @Override
    public String toString() {
        return "AuditReason[" + code + "]";
    }
}
