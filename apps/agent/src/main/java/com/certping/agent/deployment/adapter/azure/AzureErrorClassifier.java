// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.management.exception.ManagementError;
import com.azure.core.management.exception.ManagementException;

import java.util.List;
import java.util.Locale;

public final class AzureErrorClassifier {

    public static final String PERMISSION_DENIED = "DEPLOY_AZURE_PERMISSION_DENIED";

    // Azure reports some missing role assignments with a non-403 status, e.g. HTTP 409
    // ApplicationGatewayInsufficientPermissionOnSubnet, so the error code decides too.
    private static final List<String> PERMISSION_CODE_MARKERS =
            List.of("INSUFFICIENTPERMISSION", "AUTHORIZATIONFAILED", "FORBIDDEN");

    private AzureErrorClassifier() {}

    public static boolean isPermissionDenied(HttpResponseException e) {
        int status = e.getResponse() != null ? e.getResponse().getStatusCode() : -1;
        if (status == 403) {
            return true;
        }
        return e instanceof ManagementException me && hasPermissionCode(me.getValue(), 0);
    }

    private static boolean hasPermissionCode(ManagementError err, int depth) {
        if (err == null || depth > 5) {
            return false;
        }
        if (err.getCode() != null) {
            String code = err.getCode().toUpperCase(Locale.ROOT);
            if (PERMISSION_CODE_MARKERS.stream().anyMatch(code::contains)) {
                return true;
            }
        }
        List<? extends ManagementError> details = err.getDetails();
        if (details != null) {
            for (ManagementError detail : details) {
                if (hasPermissionCode(detail, depth + 1)) {
                    return true;
                }
            }
        }
        return false;
    }
}
