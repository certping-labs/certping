// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpResponse;
import com.azure.core.management.exception.ManagementError;
import com.azure.core.management.exception.ManagementException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AzureErrorClassifierTest {

    @Test
    void conflictStatusWithInsufficientPermissionCode_isPermissionDenied() {
        ManagementError error = new ManagementError("ApplicationGatewayInsufficientPermissionOnSubnet", "no join");
        assertThat(AzureErrorClassifier.isPermissionDenied(management(409, error))).isTrue();
    }

    @Test
    void conflictStatusWithConflictCode_isNotPermissionDenied() {
        ManagementError error = new ManagementError("Conflict", "Another operation is in progress");
        assertThat(AzureErrorClassifier.isPermissionDenied(management(409, error))).isFalse();
    }

    @Test
    void conflictStatusWithoutErrorBody_isNotPermissionDenied() {
        assertThat(AzureErrorClassifier.isPermissionDenied(management(409, null))).isFalse();
    }

    @Test
    void forbiddenStatus_isPermissionDenied() {
        assertThat(AzureErrorClassifier.isPermissionDenied(http(403))).isTrue();
        assertThat(AzureErrorClassifier.isPermissionDenied(management(403, null))).isTrue();
    }

    @Test
    void authorizationFailedCodes_arePermissionDenied() {
        assertThat(AzureErrorClassifier.isPermissionDenied(
                management(400, new ManagementError("AuthorizationFailed", "x")))).isTrue();
        assertThat(AzureErrorClassifier.isPermissionDenied(
                management(400, new ManagementError("LinkedAuthorizationFailed", "x")))).isTrue();
    }

    @Test
    void nestedDetailCode_isPermissionDenied() {
        ManagementError detail = mock(ManagementError.class);
        when(detail.getCode()).thenReturn("KeyVaultAccessForbidden");
        ManagementError root = mock(ManagementError.class);
        when(root.getCode()).thenReturn("ApplicationGatewayKeyVaultSecretException");
        Mockito.<List<? extends ManagementError>>when(root.getDetails()).thenReturn(List.of(detail));

        assertThat(AzureErrorClassifier.isPermissionDenied(management(400, root))).isTrue();
    }

    @Test
    void otherStatusesWithoutPermissionCode_areNotPermissionDenied() {
        assertThat(AzureErrorClassifier.isPermissionDenied(http(401))).isFalse();
        assertThat(AzureErrorClassifier.isPermissionDenied(http(404))).isFalse();
        assertThat(AzureErrorClassifier.isPermissionDenied(new HttpResponseException("no response", null)))
                .isFalse();
    }

    private static ManagementException management(int status, ManagementError error) {
        return new ManagementException("azure-" + status, response(status), error);
    }

    private static HttpResponseException http(int status) {
        return new HttpResponseException("http-" + status, response(status));
    }

    private static HttpResponse response(int status) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.getStatusCode()).thenReturn(status);
        return response;
    }
}
