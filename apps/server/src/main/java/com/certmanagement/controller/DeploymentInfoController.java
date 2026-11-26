// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.service.AdminUserService;
import com.certmanagement.dto.featureflags.DeploymentInfoDto;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public deployment metadata endpoint.
 *
 * <p>Unauthenticated by design: the frontend calls this on app boot, before a user has logged in,
 * to know whether first-run setup is needed, which sign-in options to show and whether email works.
 * See {@link com.certmanagement.config.SecurityConfig} for the permit rule that exposes
 * {@link Paths#DEPLOYMENT_INFO} publicly.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Deployment Info", description = "Public deployment metadata for the web app")
public class DeploymentInfoController {

    private final AdminUserService adminUserService;
    private final com.certmanagement.security.oidc.PlatformOidcRegistration platformOidcRegistration;
    private final org.springframework.core.env.Environment environment;

    @GetMapping(Paths.DEPLOYMENT_INFO)
    @Operation(
            summary = "Get deployment metadata",
            description = "Returns whether first-run setup is required, the configured single sign-on button "
                    + "and whether this installation can send email. Public: no authentication required."
    )
    public ResponseEntity<DeploymentInfoDto> getDeploymentInfo() {
        String agentTransport = "GATEWAY";
        DeploymentInfoDto.SsoLogin ssoLogin = platformOidcRegistration.configured()
                ? new DeploymentInfoDto.SsoLogin(platformOidcRegistration.displayName(),
                        "/oauth2/authorization/" + com.certmanagement.security.oidc.PlatformOidcProperties.REGISTRATION_ID)
                : null;
        // Mail goes out only when MAIL_HOST is set.
        boolean emailEnabled = !environment.getProperty("MAIL_HOST", "").isBlank();
        return ResponseEntity.ok(new DeploymentInfoDto(agentTransport, adminUserService.isSetupRequired(), ssoLogin,
                emailEnabled));
    }
}
