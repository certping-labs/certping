// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.cloud.gcp;

import com.certping.agent.deployment.adapter.gcp.GcpDeploymentAuthHelper;
import com.certping.agent.exception.PermanentAgentException;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

/**
 * Single entry point for GCP credential resolution. Wraps the existing
 * {@link GcpDeploymentAuthHelper#buildCredentials} and adds explicit auth-mode dispatch
 * plus optional service-account impersonation for {@code WORKLOAD_IDENTITY}.
 */
@Slf4j
@Component
public class GcpCloudCredentialResolver {

    private static final List<String> CLOUD_PLATFORM_SCOPES =
            Collections.singletonList(GcpDeploymentAuthHelper.CLOUD_PLATFORM_SCOPE);

    /** Default impersonation token lifetime when {@code impersonateServiceAccount} is set. */
    private static final int IMPERSONATION_LIFETIME_SECONDS = 3600;

    public GoogleCredentials resolve(GcpAuthMode mode, GcpAuthScope scope, GcpAuthSecret kv, String context) {
        if (mode == null) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " credential is missing 'authMode'");
        }
        GcpAuthSecret secret = kv != null ? kv : GcpAuthSecret.empty();
        GcpAuthScope safeScope = scope != null ? scope : new GcpAuthScope(null, null, null);

        GoogleCredentials base = switch (mode) {
            case SERVICE_ACCOUNT_KEY -> resolveServiceAccountKey(secret, context);
            case WORKLOAD_IDENTITY -> resolveWorkloadIdentity(context);
        };

        if (safeScope.impersonateServiceAccount() != null && !safeScope.impersonateServiceAccount().isBlank()) {
            log.debug("{}: impersonating service account {}", context, safeScope.impersonateServiceAccount());
            return ImpersonatedCredentials.create(
                    base,
                    safeScope.impersonateServiceAccount(),
                    null,
                    CLOUD_PLATFORM_SCOPES,
                    IMPERSONATION_LIFETIME_SECONDS);
        }
        return base;
    }

    private GoogleCredentials resolveServiceAccountKey(GcpAuthSecret kv, String context) {
        if (!kv.hasKey()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    context + " SERVICE_ACCOUNT_KEY auth mode requires serviceAccountJson "
                            + "(or serviceAccountJsonBase64) in KV secret");
        }
        log.debug("{}: building SERVICE_ACCOUNT_KEY credentials", context);
        return GcpDeploymentAuthHelper.buildCredentials(
                kv.serviceAccountJson(), kv.serviceAccountJsonBase64(), context);
    }

    private GoogleCredentials resolveWorkloadIdentity(String context) {
        log.debug("{}: using WORKLOAD_IDENTITY (application default credentials)", context);
        // buildCredentials with both nulls falls through to GoogleCredentials.getApplicationDefault()
        return GcpDeploymentAuthHelper.buildCredentials(null, null, context);
    }
}
