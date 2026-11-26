// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.google.auth.oauth2.GoogleCredentials;
import org.springframework.stereotype.Service;

/**
 * Central GCP authentication for all deployment adapters (Certificate Manager, ALB, Proxy NLB, API GW).
 * Builds {@link GoogleCredentials} from inline JSON, Base64-encoded JSON, or Application Default Credentials.
 */
@Service
public class GcpAuthService {

    /**
     * @param serviceAccountKeyJson     optional raw service account JSON string
     * @param serviceAccountKeyJsonBase64 optional Base64-encoded service account JSON
     * @param context                     label for error messages (e.g. "GCP ALB")
     */
    public GoogleCredentials credentials(String serviceAccountKeyJson,
                                         String serviceAccountKeyJsonBase64,
                                         String context) {
        return GcpDeploymentAuthHelper.buildCredentials(
                serviceAccountKeyJson, serviceAccountKeyJsonBase64, context);
    }
}
