// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import jakarta.persistence.LockModeType;
import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;

import java.lang.reflect.Method;
import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IotDeviceCertificateRepositoryContractTest {

    @Test
    void deviceSyncSelectionLocksCertificatesUntilTheRequestIsRecorded() throws Exception {
        Method method = IotDeviceCertificateRepository.class.getMethod(
                "findCurrentForDeviceSync", Long.class, List.class, OffsetDateTime.class);

        assertThat(method.getAnnotation(Lock.class))
                .extracting(Lock::value)
                .isEqualTo(LockModeType.PESSIMISTIC_WRITE);
    }

    @Test
    void passiveRenewalOnlySupersedesIssuedLeafCertificates() throws Exception {
        Method method = IotDeviceCertificateRepository.class.getMethod(
                "findSupersededMonitoredCertificates",
                Long.class, Long.class, Long.class, Long.class, OffsetDateTime.class);

        assertThat(queryText(method))
                .contains("c.status = 'ISSUED'")
                .contains("c.certificateAuthority = false");
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
