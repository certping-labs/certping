// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for {@link MdcIds}. */
class MdcIdsTest {

    @BeforeEach
    @AfterEach
    void clear() {
        MDC.clear();
    }

    @Test
    void requestIdReturnsMdcValueWhenPresent() {
        MDC.put("requestId", "req-123");
        assertThat(MdcIds.requestId()).isEqualTo("req-123");
    }

    @Test
    void requestIdMintsOrphanWhenMdcEmpty() {
        assertThat(MdcIds.requestId()).startsWith("req-orphan-");
    }

    @Test
    void requestIdMintsOrphanWhenMdcBlank() {
        MDC.put("requestId", "");
        assertThat(MdcIds.requestId()).startsWith("req-orphan-");
    }

    @Test
    void correlationIdReturnsMdcValueWhenPresent() {
        MDC.put("correlationId", "corr-abc");
        assertThat(MdcIds.correlationId()).isEqualTo("corr-abc");
    }

    @Test
    void correlationIdReturnsNullWhenEmptyOrUnknown() {
        assertThat(MdcIds.correlationId()).isNull();
        MDC.put("correlationId", "");
        assertThat(MdcIds.correlationId()).isNull();
        MDC.put("correlationId", "unknown");
        assertThat(MdcIds.correlationId()).isNull();
    }
}
