// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.featureflags.DeploymentInfoDto;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/** The public deployment-info endpoint: first-run setup, the sign-in button, email and the agent transport. */
@ExtendWith(MockitoExtension.class)
class DeploymentInfoControllerTest {

    @Mock private com.certmanagement.service.AdminUserService adminUserService;

    private DeploymentInfoController controller;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        controller = new DeploymentInfoController(adminUserService, oidc(null),
                new org.springframework.mock.env.MockEnvironment());
    }

    /** The platform OIDC provider: unconfigured, or configured with {@code label}. */
    private static com.certmanagement.security.oidc.PlatformOidcRegistration oidc(String label) {
        com.certmanagement.security.oidc.PlatformOidcProperties props =
                new com.certmanagement.security.oidc.PlatformOidcProperties();
        if (label != null) {
            props.setIssuerUri("https://idp.example.com");
            props.setClientId("certping");
            props.setClientSecret("secret");
            props.setOrganization("acme");
            props.setDisplayName(label);
        }
        return new com.certmanagement.security.oidc.PlatformOidcRegistration(props, null, null);
    }

    @Test
    void ssoLoginIsNullWithoutAProviderAndNamesTheButtonWithOne() {
        assertThat(controller.getDeploymentInfo().getBody().getSsoLogin()).isNull();

        DeploymentInfoController withSso = new DeploymentInfoController(adminUserService, oidc("Okta"),
                new org.springframework.mock.env.MockEnvironment());
        DeploymentInfoDto.SsoLogin sso = withSso.getDeploymentInfo().getBody().getSsoLogin();
        assertThat(sso.label()).isEqualTo("Okta");
        assertThat(sso.startPath()).isEqualTo("/oauth2/authorization/sso");
    }

    @Test
    void theAgentTransportIsAlwaysTheGateway() {
        ResponseEntity<DeploymentInfoDto> response = controller.getDeploymentInfo();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getAgentTransport()).isEqualTo("GATEWAY");
        assertThat(new DeploymentInfoDto().getAgentTransport()).isEqualTo("GATEWAY");
    }

    @Test
    void aFreshInstallReportsSetupRequired() {
        when(adminUserService.isSetupRequired()).thenReturn(true);

        assertThat(controller.getDeploymentInfo().getBody().isSetupRequired()).isTrue();
    }

    @Test
    void emailIsOffWithoutAMailHost() {
        assertThat(controller.getDeploymentInfo().getBody().isEmailEnabled()).isFalse();

        DeploymentInfoController withMail = new DeploymentInfoController(adminUserService, oidc(null),
                new org.springframework.mock.env.MockEnvironment().withProperty("MAIL_HOST", "smtp.example.com"));
        assertThat(withMail.getDeploymentInfo().getBody().isEmailEnabled()).isTrue();
    }
}
