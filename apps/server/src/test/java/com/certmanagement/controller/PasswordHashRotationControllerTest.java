// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.service.PasswordHashRotationService;
import com.certmanagement.service.PasswordHashRotationService.InventoryReport;
import com.certmanagement.service.PasswordHashRotationService.RotationReport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordHashRotationControllerTest {

    @Mock private PasswordHashRotationService rotationService;

    @InjectMocks private PasswordHashRotationController controller;

    @Test
    void inventory_delegates() {
        InventoryReport report = new InventoryReport("v2", Map.of("v1", 3L, "v2", 10L));
        when(rotationService.inventory()).thenReturn(report);

        InventoryReport result = controller.inventory();

        assertThat(result).isSameAs(report);
        assertThat(result.activeVersion()).isEqualTo("v2");
    }

    @Test
    void rotate_delegatesWithBatchSize() {
        RotationReport report = new RotationReport("v2", 5, 1, Map.of("v1", 5), Map.of("v2", 15L));
        when(rotationService.rotateAllToActive(250)).thenReturn(report);

        RotationReport result = controller.rotate(250);

        assertThat(result).isSameAs(report);
        assertThat(result.migrated()).isEqualTo(5);
    }
}
