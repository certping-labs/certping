// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.featureflags;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Public deployment metadata served by {@code GET /api/v1/deployment-info}: what the web app needs to
 * know about this installation before anyone has signed in.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeploymentInfoDto {

    /**
     * How agents connect. Always {@code "GATEWAY"} (HTTPS with agent tokens); the field stays so
     * the web app can pick the agent setup it shows.
     */
    private String agentTransport = "GATEWAY";

    /** True until the first Platform Super Admin exists; the web app sends visitors to setup. */
    private boolean setupRequired;

    /**
     * The environment-configured OpenID Connect provider ({@code CERTPING_OIDC_*}), when there is one:
     * the web app shows a sign-in button with {@code label} that opens {@code startPath} on the API
     * origin. Null when sign-in is local only.
     */
    private SsoLogin ssoLogin;

    /**
     * Whether this installation can send email. False on a self-hosted install without
     * {@code MAIL_HOST}: the login page then says to ask an administrator instead of offering a reset email.
     */
    private boolean emailEnabled = true;

    public record SsoLogin(String label, String startPath) {
    }
}
