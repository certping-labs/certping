// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.support.auth.AuthenticatedUser;
import com.certmanagement.support.auth.CurrentAuthenticatedUser;
import com.certmanagement.support.integrations.api.model.CreateIntegrationRequest;
import com.certmanagement.support.integrations.api.model.IntegrationResponse;
import com.certmanagement.support.integrations.api.model.UpdateIntegrationRequest;
import com.certmanagement.support.integrations.application.IntegrationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockMakers;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@ExtendWith(MockitoExtension.class)
class IntegrationControllerTest {

    @Mock private CurrentAuthenticatedUser currentAuthenticatedUser;
    @Mock private IntegrationService integrationService;

    @InjectMocks private IntegrationController controller;

    private final AuthenticatedUser user = new AuthenticatedUser(
            1L, "u@example.com", "10", "Acme", List.of(), List.of(), "local");

    private static <T> T inline(Class<T> type) {
        return mock(type, withSettings().mockMaker(MockMakers.INLINE));
    }

    @Test
    void createIntegration_returnsCreated() {
        when(currentAuthenticatedUser.getRequired()).thenReturn(user);
        CreateIntegrationRequest req = inline(CreateIntegrationRequest.class);
        IntegrationResponse resp = inline(IntegrationResponse.class);
        when(integrationService.createIntegration(user, req)).thenReturn(resp);

        ResponseEntity<IntegrationResponse> response = controller.createIntegration(req);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isSameAs(resp);
    }

    @Test
    void listIntegrations_delegates() {
        when(currentAuthenticatedUser.getRequired()).thenReturn(user);
        List<IntegrationResponse> list = List.of(inline(IntegrationResponse.class));
        when(integrationService.listIntegrations(user)).thenReturn(list);

        List<IntegrationResponse> result = controller.listIntegrations();

        assertThat(result).isSameAs(list);
    }

    @Test
    void getIntegration_delegates() {
        when(currentAuthenticatedUser.getRequired()).thenReturn(user);
        IntegrationResponse resp = inline(IntegrationResponse.class);
        when(integrationService.getIntegration(user, 5L)).thenReturn(resp);

        IntegrationResponse result = controller.getIntegration(5L);

        assertThat(result).isSameAs(resp);
    }

    @Test
    void updateIntegration_delegates() {
        when(currentAuthenticatedUser.getRequired()).thenReturn(user);
        UpdateIntegrationRequest req = inline(UpdateIntegrationRequest.class);
        IntegrationResponse resp = inline(IntegrationResponse.class);
        when(integrationService.updateIntegration(user, 5L, req)).thenReturn(resp);

        IntegrationResponse result = controller.updateIntegration(5L, req);

        assertThat(result).isSameAs(resp);
    }

    @Test
    void deleteIntegration_returnsNoContent() {
        when(currentAuthenticatedUser.getRequired()).thenReturn(user);

        ResponseEntity<Void> response = controller.deleteIntegration(5L);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(integrationService).deleteIntegration(user, 5L);
    }
}
