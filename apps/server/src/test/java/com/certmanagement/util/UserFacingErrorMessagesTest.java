// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import org.junit.jupiter.api.Test;

import static com.certmanagement.util.UserFacingErrorMessages.forCode;
import static com.certmanagement.util.UserFacingErrorMessages.resolveCode;
import static org.assertj.core.api.Assertions.assertThat;

class UserFacingErrorMessagesTest {

    @Test
    void specificCodesGetBespokeMessages() {
        assertThat(forCode("RETRY_GIVE_UP")).contains("re-trigger");
        assertThat(forCode("ACME_RATE_LIMITED")).contains("Let's Encrypt");
        assertThat(forCode("DEPLOY_AUTH_INVALID")).contains("Integrations");
        assertThat(forCode("ACME_CHALLENGE_INVALID")).contains("_acme-challenge");
    }

    @Test
    void throttleFamilyVariesByProvider() {
        assertThat(forCode("DEPLOY_PROVIDER_THROTTLED")).contains("cloud provider").contains("rate-limiting");
        assertThat(forCode("KV_PROVIDER_THROTTLED")).contains("rate-limiting");
        assertThat(forCode("DNS_PROVIDER_THROTTLED")).contains("DNS provider");
        assertThat(forCode("CA_PROVIDER_THROTTLED")).contains("certificate authority");
    }

    @Test
    void quotaFamilyGivesResourceLimitGuidance() {
        // Quota errors must NOT be mislabeled as a credentials/auth problem.
        assertThat(forCode("DEPLOY_GCP_QUOTA_EXCEEDED"))
                .contains("quota").contains("SSL certificates");
        assertThat(forCode("DEPLOY_GCP_QUOTA_EXCEEDED"))
                .doesNotContain("credentials");
        assertThat(forCode("SOME_RESOURCE_EXHAUSTED")).contains("quota");
    }

    @Test
    void credentialFamilyCoversAuthVariants() {
        assertThat(forCode("DEPLOY_K8S_CREDENTIAL_INVALID")).contains("credentials");
        assertThat(forCode("KV_ACCESS_DENIED")).contains("key vault");
        assertThat(forCode("AZURE_KV_AUTH_FAILED")).contains("credentials");
        assertThat(forCode("DNS_CREDENTIAL_INVALID")).contains("DNS provider").contains("Credentials");
        assertThat(forCode("EJBCA_OAUTH_REJECTED")).contains("CA credential").contains("Connectors");
        assertThat(forCode("AKAMAI_CRED_MISSING")).contains("No credential is configured");
    }

    @Test
    void domainValidationFamily() {
        assertThat(forCode("ACME_CHALLENGE_FAILED")).contains("Domain validation");
        assertThat(forCode("ACME_DNS_CHALLENGE_FAILED")).contains("Domain validation");
    }

    @Test
    void notFoundConflictAndTimeoutFamilies() {
        assertThat(forCode("DEPLOY_SECRET_NOT_FOUND")).contains("wasn't found");
        assertThat(forCode("DEPLOY_RESOURCE_NOT_FOUND")).contains("wasn't found");
        assertThat(forCode("DEPLOY_AZURE_CONFLICT")).contains("conflicting");
        assertThat(forCode("DEPLOY_AKAMAI_TIMEOUT")).contains("timed out");
    }

    @Test
    void certAndConfigFamilies() {
        assertThat(forCode("CERT_FORMAT_INVALID")).contains("certificate was rejected");
        assertThat(forCode("DEPLOY_CERT_REJECTED")).contains("certificate was rejected");
        assertThat(forCode("DEPLOY_TARGETS_INVALID")).contains("configuration");
        assertThat(forCode("DEPLOY_K8S_CONFIG_INVALID")).contains("configuration");
    }

    @Test
    void unmappedCodesStillNameTheSubsystemThatFailed() {
        assertThat(forCode("DEPLOY_AZURE_KV_IMPORT_FAILED")).contains("Azure");
        assertThat(forCode("DEPLOY_F5_SYNC_FAILED")).contains("F5 BIG-IP");
        assertThat(forCode("EJBCA_SERVER_ERROR")).contains("EJBCA");
        assertThat(forCode("GLOBALSIGN_API_ERROR")).contains("GlobalSign");
        assertThat(forCode("SMALLSTEP_TRUST_INVALID")).contains("Smallstep");
        assertThat(forCode("KV_READ_FAILED")).contains("key vault");
        assertThat(forCode("SM_READ_FAILED")).contains("secret store");
        assertThat(forCode("DISCOVERY_AWS_SDK_ERROR")).contains("scanning");
        assertThat(forCode("CSR_BUILD_FAILED")).contains("certificate request");
    }

    @Test
    void noCodeFallsToTheGenericMessage() {
        // Every code the agent can emit must produce copy that names a cause or a system.
        // A sample across every subsystem — extend it when the agent adds a code family.
        for (String code : new String[]{
                "KV_READ_FAILED", "DNS_NS_LOOKUP_FAILED", "EJBCA_UNEXPECTED_REDIRECT",
                "GLOBALSIGN_POLICY_UNSUPPORTED", "SMALLSTEP_JWK_UNSUPPORTED",
                "PROFILE_TYPE_UNSUPPORTED", "SYNC_DEVICE_REJECTED", "DISCOVERY_UNKNOWN_TARGET",
                "REVOCATION_TRANSIENT", "ACME_NETWORK_ERROR",
                "DEPLOY_CLOUDFRONT_ERROR", "SCEP_ENDPOINT_INVALID", "MANUAL_TXT_REQUEST_INVALID"}) {
            assertThat(forCode(code))
                    .as("code %s must not fall through to the generic message", code)
                    .doesNotContain("The operation could not be completed")
                    .doesNotContain("The provider couldn't complete the operation");
        }
    }

    @Test
    void permanentFailuresDoNotTellTheUserToRetry() {
        // Retrying these can never succeed — the copy must name a fix instead.
        assertThat(forCode("DNS_NS_LOOKUP_FAILED")).contains("nameservers").contains("registration");
        assertThat(forCode("CSR_KEYTYPE_UNSUPPORTED")).contains("key type");
        assertThat(forCode("DEPLOY_KEY_ENCRYPTED")).contains("passphrase");
        assertThat(forCode("REVOCATION_INVALID_STATE")).doesNotContain("try again");
    }

    @Test
    void ourOwnDefectsAreNotBlamedOnTheCustomersProvider() {
        assertThat(forCode("UNKNOWN_MESSAGE_TYPE")).contains("on the server");
        assertThat(forCode("MISSING_ORGANIZATION_ID")).contains("on the server");
        assertThat(forCode("DEPLOY_RESULT_NULL_ARN")).contains("on the server");
        assertThat(forCode("ORGANIZATION_ID_MISSING")).contains("on the server");
        // ...and never point the customer at a provider that was not involved.
        assertThat(forCode("KV_READ_FAILED")).doesNotContain("The provider");
    }

    @Test
    void missingCredentialsAreNotReportedAsRejectedOnes() {
        // Two different problems with two different fixes — merging them into
        // "rejected or are missing" leaves the user guessing which one they have.
        assertThat(forCode("EJBCA_CREDENTIAL_MISSING")).contains("No credential is configured");
        assertThat(forCode("EJBCA_CREDENTIAL_INVALID")).contains("rejected");
        assertThat(forCode("DEPLOY_CREDENTIAL_MISSING")).doesNotContain("rejected");
        assertThat(forCode("DEPLOY_AZURE_CLIENT_ID_MISSING")).contains("Client ID").doesNotContain("rejected");
    }

    @Test
    void azurePermissionDeniedIsAPermissionProblemNotARejectedCredential() {
        String message = forCode("DEPLOY_AZURE_PERMISSION_DENIED");
        assertThat(message).contains("permission").contains("agent log");
        assertThat(message).doesNotContain("rejected").doesNotContain("conflicting");
        assertThat(message).doesNotContain("\u2014").doesNotContain("\u2013");
    }

    @Test
    void secretStoreFailuresNameTheStoreNotADeploymentTarget() {
        // The agent reads credentials from the customer's own secret store, so these are
        // neither a CertPing outage nor a deployment-target problem.
        assertThat(forCode("KV_READ_FAILED")).contains("key vault");
        assertThat(forCode("KV_ACCESS_DENIED")).contains("key vault");
        assertThat(forCode("KV_PROVIDER_THROTTLED")).contains("key vault");
        assertThat(forCode("SM_ACCESS_DENIED")).contains("secret store");
        assertThat(forCode("KV_PROVIDER_THROTTLED")).doesNotContain("cloud provider");
        assertThat(forCode("KV_ACCESS_DENIED")).doesNotContain("Integrations");
    }

    @Test
    void awsAndGcpSecretStoresAreNotCalledAKeyVault() {
        // KV_* is Azure Key Vault; SM_* is AWS Secrets Manager / GCP Secret Manager. Naming the
        // wrong product sends those customers looking in a console they don't use.
        for (String code : new String[]{
                "SM_ACCESS_DENIED", "SM_READ_FAILED", "SM_HANDLE_BLANK",
                "SM_HANDLE_INVALID", "SM_PROVIDER_THROTTLED", "SECRET_READ_FAILED"}) {
            assertThat(forCode(code))
                    .as("code %s must not name a key vault", code)
                    .contains("secret store")
                    .doesNotContain("key vault");
        }
    }

    @Test
    void unknownDnsProviderCoversBlankAndUnsupportedProviders() {
        // The code is raised both for a blank provider and for one we don't support, so the copy
        // must not promise that a plain retry will resolve it.
        assertThat(forCode("DNS_PROVIDER_UNKNOWN"))
                .contains("supported DNS provider")
                .contains("manual mode");
    }

    @Test
    void missingSettingsAreScopedToTheSubsystemThatOwnsThem() {
        // A "_MISSING" suffix used to route every subsystem to deployment wording —
        // telling EJBCA users to review deployment target settings.
        assertThat(forCode("SMALLSTEP_CONFIG_MISSING")).contains("certificate authority");
        assertThat(forCode("SMALLSTEP_CONFIG_MISSING")).doesNotContain("deployment");
        assertThat(forCode("DEPLOY_K8S_CONFIG_MISSING")).contains("deployment");
    }

    @Test
    void caGuidanceNamesTheScreenThatHoldsThatCasCredential() {
        // EJBCA / GlobalSign / Smallstep are configured as machine-identity connectors;
        // DigiCert / Akamai CPS credentials live on the Credentials screen.
        assertThat(forCode("EJBCA_CREDENTIAL_MISSING")).contains("Connectors");
        assertThat(forCode("GLOBALSIGN_CONFIG_MISSING")).contains("Connectors");
        assertThat(forCode("SMALLSTEP_CONFIG_MISSING")).contains("Connectors");
        assertThat(forCode("EJBCA_CREDENTIAL_MISSING")).doesNotContain("Credentials");
        assertThat(forCode("AKAMAI_CRED_MISSING")).contains("Credentials");
        assertThat(forCode("DIGICERT_CREDENTIAL_INVALID")).contains("Credentials");
    }

    @Test
    void deviceSourceProblemsPointAtConnectors() {
        // Device sources are set up under Connectors — sending users to Integrations for a
        // permission failure contradicts the wording used for their config errors.
        assertThat(forCode("PLATFORM_PERMISSION_DENIED")).contains("Connectors");
        assertThat(forCode("INTUNE_CONFIGURATION_PERMISSION_DENIED")).contains("Connectors");
        assertThat(forCode("PLATFORM_PERMISSION_DENIED")).doesNotContain("Integrations");
        assertThat(forCode("PLATFORM_NOT_CONFIGURED")).contains("Connectors");
    }

    @Test
    void dnsCredentialGuidancePointsAtTheCredentialsScreen() {
        // DNS credentials live under Credentials, not Integrations — sending users to the
        // wrong screen is worse than giving no destination at all.
        assertThat(forCode("DNS_CREDENTIAL_INVALID")).contains("Credentials");
        assertThat(forCode("DNS_CREDENTIAL_INVALID")).doesNotContain("Integrations");
    }

    @Test
    void messagesUseNoEmOrEnDashes() {
        // House style for customer-facing copy: plain sentences and commas only.
        for (String code : new String[]{
                "KV_PROVIDER_THROTTLED", "ACME_CHALLENGE_INVALID", "DEPLOY_AKAMAI_TIMEOUT",
                "DEPLOY_GCP_QUOTA_EXCEEDED", "CERT_FORMAT_INVALID", "UNKNOWN_MESSAGE_TYPE",
                "ACME_NETWORK_ERROR", "RETRY_GIVE_UP"}) {
            assertThat(forCode(code))
                    .as("code %s must not use a dash where a sentence break belongs", code)
                    .doesNotContain("\u2014")
                    .doesNotContain("\u2013");
        }
    }

    @Test
    void unknownAndNullCodesNeverLeakDetail() {
        String unknown = forCode("SOME_TOTALLY_UNKNOWN_THING");
        assertThat(unknown).isNotBlank();
        assertThat(unknown).doesNotContain("SOME_TOTALLY_UNKNOWN_THING");
        assertThat(forCode(null)).isNotBlank();
        assertThat(forCode("")).isNotBlank();
        // A generic-failure code must not echo the raw code either.
        assertThat(forCode("DEPLOY_AZURE_KV_IMPORT_FAILED")).doesNotContain("KV_IMPORT");
    }

    @Test
    void retryWrapperUnwrapsToInnerReason() {
        assertThat(forCode("RETRY_GIVE_UP", "ACME_RATE_LIMITED")).contains("Let's Encrypt");
        assertThat(forCode("RETRY_GIVE_UP", null)).contains("re-trigger");
    }

    @Test
    void resolveCodeUnwrapsRetryWrapperForPersistence() {
        // The deployment failure path stores the resolved code so the later message is specific.
        assertThat(resolveCode("RETRY_GIVE_UP", "DEPLOY_PROVIDER_THROTTLED"))
                .isEqualTo("DEPLOY_PROVIDER_THROTTLED");
        assertThat(forCode(resolveCode("RETRY_GIVE_UP", "DEPLOY_AKAMAI_TIMEOUT")))
                .contains("timed out");
        // No inner reason (null/blank) or a non-wrapper code is returned unchanged.
        assertThat(resolveCode("RETRY_GIVE_UP", null)).isEqualTo("RETRY_GIVE_UP");
        assertThat(resolveCode("RETRY_GIVE_UP", "   ")).isEqualTo("RETRY_GIVE_UP");
        assertThat(resolveCode("DEPLOY_CERT_REJECTED", "ignored")).isEqualTo("DEPLOY_CERT_REJECTED");
    }
}
