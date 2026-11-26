// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.aspect.FeatureGatedAspect;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.cbom.CbomProjectionService;
import com.certmanagement.service.cbom.PqcReadinessService;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.data.domain.Pageable;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/** Every PQC readiness and CBOM endpoint is refused while PQC_READINESS is off for the org. */
@ExtendWith(MockitoExtension.class)
class PqcFeatureGateTest {

    private static final long ORG_ID = 42L;

    @Mock private FeatureFlagService featureFlagService;
    @Mock private PqcReadinessService pqcReadinessService;
    @Mock private CbomProjectionService cbomProjectionService;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "user@test.com");
        doThrow(new FeatureDisabledException(FeatureFlags.PQC_READINESS))
                .when(featureFlagService).assertEnabled(FeatureFlags.PQC_READINESS, ORG_ID);
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    private <T> T gated(T controller) {
        AspectJProxyFactory factory = new AspectJProxyFactory(controller);
        factory.setProxyTargetClass(true);
        factory.addAspect(new FeatureGatedAspect(featureFlagService));
        return factory.getProxy();
    }

    @Test
    void pqcReadinessSummary_isRefusedWhenFlagOff() {
        PqcReadinessController controller = gated(new PqcReadinessController(pqcReadinessService));

        assertThatThrownBy(controller::getPqcReadiness).isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(pqcReadinessService);
    }

    @Test
    void pqcReadinessCertificates_isRefusedWhenFlagOff() {
        PqcReadinessController controller = gated(new PqcReadinessController(pqcReadinessService));

        assertThatThrownBy(() -> controller.listCertificates(null, Pageable.ofSize(15)))
                .isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(pqcReadinessService);
    }

    @Test
    void cbomDownload_isRefusedWhenFlagOff() throws Exception {
        CbomController controller = gated(new CbomController(cbomProjectionService));

        assertThatThrownBy(() -> controller.downloadCbom(mock(HttpServletResponse.class)))
                .isInstanceOf(FeatureDisabledException.class);
        verifyNoInteractions(cbomProjectionService);
    }
}
