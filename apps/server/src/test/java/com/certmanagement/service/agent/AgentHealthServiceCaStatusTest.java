// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.messaging.model.AgentCaStatus;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class AgentHealthServiceCaStatusTest {

    private final AgentCaStatusStore store = mock(AgentCaStatusStore.class);
    private final AgentHealthService service = new AgentHealthService(null, null, null, null, null);

    @Test
    void storesUnderTheAuthenticatedOrganizationAndToken() {
        service.setCaStatusStore(store);
        AgentCaStatus status = new AgentCaStatus();

        service.saveCaStatus("12", 34L, status);

        verify(store).save(12L, 34L, status);
    }

    @Test
    void nothingToStore_orNoStore_isANoOp() {
        service.saveCaStatus("12", 34L, new AgentCaStatus());
        service.setCaStatusStore(store);
        service.saveCaStatus("12", 34L, null);
        verify(store, never()).save(anyLong(), any(), any());
    }

    @Test
    void aStoreFailureDoesNotEscape() {
        service.setCaStatusStore(store);
        doThrow(new IllegalStateException("db down")).when(store).save(anyLong(), any(), any());
        service.saveCaStatus("12", null, new AgentCaStatus());
        service.saveCaStatus("not-a-number", null, new AgentCaStatus());
    }
}
