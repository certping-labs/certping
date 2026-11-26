// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.messaging.model.AgentInfo;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class AgentHealthServiceAgentInfoTest {

    private final AgentInfoStore store = mock(AgentInfoStore.class);
    private final AgentHealthService service = new AgentHealthService(null, null, null, null, null);

    @Test
    void recordsUnderTheAuthenticatedOrganizationAndToken_withOrWithoutInfo() {
        service.setAgentInfoStore(store);
        AgentInfo info = AgentInfo.builder().version("0.2.0").build();

        service.saveAgentInfo("12", 34L, info);
        service.saveAgentInfo("12", 34L, null);

        verify(store).recordHeartbeat(12L, 34L, info);
        verify(store).recordHeartbeat(12L, 34L, null);
    }

    @Test
    void noTokenOrNoStoreIsANoOp() {
        service.saveAgentInfo("12", 34L, new AgentInfo());
        service.setAgentInfoStore(store);
        service.saveAgentInfo("12", null, new AgentInfo());
        service.saveAgentInfo(null, 34L, new AgentInfo());
        verify(store, never()).recordHeartbeat(anyLong(), anyLong(), any());
    }

    @Test
    void aStoreFailureDoesNotEscape() {
        service.setAgentInfoStore(store);
        doThrow(new IllegalStateException("db down")).when(store).recordHeartbeat(anyLong(), anyLong(), any());
        service.saveAgentInfo("12", 34L, new AgentInfo());
        service.saveAgentInfo("not-a-number", 34L, new AgentInfo());
    }
}
