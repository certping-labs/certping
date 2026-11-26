// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static com.certmanagement.util.UserFacingErrorMessages.forCode;
import static org.assertj.core.api.Assertions.assertThat;

/** Covers the bespoke codes, subsystem fallbacks and display names not exercised elsewhere. */
class UserFacingErrorMessagesCoverageTest {

    private static final String GENERIC = forCode(null);

    @ParameterizedTest
    @ValueSource(strings = {
            "ACME_ORDER_INVALID", "ACME_NO_AUTHORIZATIONS", "ACME_ACCOUNT_CREATE_FAILED", "ACME_ACCOUNT_LOAD_FAILED",
            "DNS_ZONE_NOT_FOUND", "DNS_ZONE_NOT_SERVICEABLE", "DNS_PROPAGATION_TIMEOUT",
            "CSR_EC_KEYSIZE_UNSUPPORTED", "CA_PRODUCT_NOT_AVAILABLE", "CA_ORDER_REJECTED", "MISSING_CA_CREDENTIAL",
            "UNKNOWN_CA_PROVIDER", "UNSUPPORTED_CA", "UNSUPPORTED_CA_FOR_MANUAL",
            "EJBCA_REST_DISABLED", "EJBCA_DISABLED", "GLOBALSIGN_DOMAIN_VERIFICATION_FAILED", "GLOBALSIGN_DOMAIN_INVALID",
            "DEPLOY_CLOUDFRONT_DEFAULT_CERT", "DEPLOY_CLOUDFRONT_IAM_CERT", "PLATFORM_NOT_SUPPORTED",
            "INTUNE_CREDENTIAL_MISSING", "DNS_ZONE_REQUIRED", "PLATFORM_TENANT_REQUIRED",
            "DNS_RECORD_WRITE_FAILED", "DISCOVERY_SCAN_FAILED", "CSR_BUILD_FAILED", "REVOCATION_FAILED",
            "SM_READ_FAILED", "SYNC_FAILED", "SCEP_ENROLL_FAILED", "PROFILE_APPLY_FAILED", "RENEWAL_FAILED"
    })
    void knownCodesGetSpecificCopyWithoutLeakingTheCode(String code) {
        String message = forCode(code);
        assertThat(message).isNotBlank().isNotEqualTo(GENERIC).doesNotContain(code);
    }

    @Test
    void codesAreNormalisedBeforeLookup() {
        assertThat(forCode("  acme_order_invalid ")).isEqualTo(forCode("ACME_ORDER_INVALID"));
    }

    @Test
    void missingDeviceSourceCredentialPointsToConnectors() {
        assertThat(forCode("INTUNE_CREDENTIAL_MISSING")).contains("device source").contains("Connectors");
        assertThat(forCode("PLATFORM_TENANT_REQUIRED")).contains("Connectors");
        assertThat(forCode("DNS_ZONE_REQUIRED")).contains("DNS");
    }

    @ParameterizedTest
    @CsvSource({
            "EJBCA_UNREACHABLE, EJBCA",
            "GLOBALSIGN_UNREACHABLE, GlobalSign",
            "SMALLSTEP_UNREACHABLE, Smallstep",
            "DIGICERT_UNREACHABLE, DigiCert",
            "AKAMAI_UNREACHABLE, Akamai CPS",
            "CA_UNREACHABLE, the configured CA"
    })
    void certificateAuthorityFailuresNameTheCa(String code, String name) {
        assertThat(forCode(code)).contains("(" + name + ")");
    }

    @ParameterizedTest
    @CsvSource({
            "DEPLOY_ACM_UPLOAD_FAILED, AWS",
            "DEPLOY_AWS_UPLOAD_FAILED, AWS",
            "DEPLOY_CLOUDFRONT_UPDATE_FAILED, CloudFront",
            "DEPLOY_CLOUDFLARE_UPLOAD_FAILED, Cloudflare",
            "DEPLOY_AZURE_UPLOAD_FAILED, Azure",
            "DEPLOY_GCP_UPLOAD_FAILED, Google Cloud",
            "DEPLOY_K8S_APPLY_FAILED, your Kubernetes cluster",
            "DEPLOY_F5_UPLOAD_FAILED, your F5 BIG-IP device",
            "DEPLOY_AKAMAI_UPLOAD_FAILED, Akamai",
            "DEPLOY_APIGW_UPDATE_FAILED, API Gateway",
            "DEPLOY_ELB_UPDATE_FAILED, your load balancer",
            "DEPLOY_STS_ASSUME_FAILED, AWS"
    })
    void deploymentFailuresNameTheTarget(String code, String target) {
        assertThat(forCode(code)).contains("deploy the certificate to " + target + ".");
    }

    @Test
    void unknownDeploymentTargetFallsBackToUnnamedWording() {
        assertThat(forCode("DEPLOY_MYSTERY_FAILED"))
                .contains("configured target")
                .doesNotContain("MYSTERY");
        assertThat(forCode("DEPLOYMENT_FAILED")).contains("configured target");
    }
}
