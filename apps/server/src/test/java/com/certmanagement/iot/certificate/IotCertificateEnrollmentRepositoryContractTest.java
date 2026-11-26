// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class IotCertificateEnrollmentRepositoryContractTest {

    @Test
    void pendingRelinkWindowOnlyIncludesActiveDeviceMatches() throws Exception {
        Method method = IotCertificateEnrollmentRepository.class.getMethod(
                "findRelinkableByDeviceSourceId", Long.class, boolean.class);

        assertThat(queryText(method))
                .contains("device.status = 'REGISTERED'")
                .contains("enrollment.source_identifier_type = 'MANAGED_DEVICE_ID'")
                .contains("enrollment.source_identifier_type = 'UNKNOWN'")
                .contains("LIMIT 500");
    }

    private static String queryText(Method method) {
        Query query = method.getAnnotation(Query.class);
        if (query != null) {
            return query.value();
        }
        NativeQuery nativeQuery = method.getAnnotation(NativeQuery.class);
        return nativeQuery == null ? null : nativeQuery.value();
    }
}
