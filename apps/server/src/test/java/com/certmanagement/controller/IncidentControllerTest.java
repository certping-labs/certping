// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.support.auth.AuthenticatedUser;
import com.certmanagement.support.auth.CurrentAuthenticatedUser;
import com.certmanagement.support.incidents.api.model.CreatePagerDutyIncidentRequest;
import com.certmanagement.support.incidents.api.model.CreatePagerDutyIncidentResponse;
import com.certmanagement.support.incidents.api.model.CreateServiceNowIncidentRequest;
import com.certmanagement.support.incidents.api.model.CreateServiceNowIncidentResponse;
import com.certmanagement.support.incidents.api.model.IncidentPageResponse;
import com.certmanagement.support.incidents.application.IncidentService;
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
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@ExtendWith(MockitoExtension.class)
class IncidentControllerTest {

    @Mock private CurrentAuthenticatedUser currentAuthenticatedUser;
    @Mock private IncidentService incidentService;

    @InjectMocks private IncidentController controller;

    private final AuthenticatedUser user = new AuthenticatedUser(
            1L, "u@example.com", "10", "Acme", List.of(), List.of(), "local");

    private static <T> T inline(Class<T> type) {
        return mock(type, withSettings().mockMaker(MockMakers.INLINE));
    }

    @Test
    void listIncidents_delegates() {
        when(currentAuthenticatedUser.getRequired()).thenReturn(user);
        IncidentPageResponse page = new IncidentPageResponse(0, 50, 0, 0, List.of());
        when(incidentService.listIncidents(user, 0, 50)).thenReturn(page);

        IncidentPageResponse result = controller.listIncidents(0, 50);

        assertThat(result).isSameAs(page);
    }

    @Test
    void createPagerDutyIncident_returnsAccepted() {
        when(currentAuthenticatedUser.getRequired()).thenReturn(user);
        CreatePagerDutyIncidentRequest req = inline(CreatePagerDutyIncidentRequest.class);
        CreatePagerDutyIncidentResponse resp =
                new CreatePagerDutyIncidentResponse("triggered", "ok", "dedup-1");
        when(incidentService.createPagerDutyIncident(user, req)).thenReturn(resp);

        ResponseEntity<CreatePagerDutyIncidentResponse> response =
                controller.createPagerDutyIncident(req);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getBody()).isSameAs(resp);
    }

    @Test
    void createServiceNowIncident_returnsCreated() {
        when(currentAuthenticatedUser.getRequired()).thenReturn(user);
        CreateServiceNowIncidentRequest req = inline(CreateServiceNowIncidentRequest.class);
        CreateServiceNowIncidentResponse resp =
                new CreateServiceNowIncidentResponse("sys-1", "INC0001", "https://record", "https://display");
        when(incidentService.createServiceNowIncident(user, req)).thenReturn(resp);

        ResponseEntity<CreateServiceNowIncidentResponse> response =
                controller.createServiceNowIncident(req);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isSameAs(resp);
    }
}
