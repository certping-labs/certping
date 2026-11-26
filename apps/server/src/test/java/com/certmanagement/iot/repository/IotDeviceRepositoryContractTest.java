// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.repository;

import org.junit.jupiter.api.Test;
import org.springframework.data.jpa.repository.NativeQuery;
import org.springframework.data.jpa.repository.Query;

import java.lang.reflect.Method;
import java.util.Collection;
import org.springframework.data.domain.Pageable;

import static org.assertj.core.api.Assertions.assertThat;

class IotDeviceRepositoryContractTest {

    @Test
    void managedDeviceIdentityLookupExcludesOrphanedRows() throws Exception {
        Method method = IotDeviceRepository.class.getMethod(
                "findRegisteredBySourceDeviceId", Long.class, String.class);

        assertThat(queryText(method))
                .contains("DeviceStatus.REGISTERED")
                .contains("d.isDeleted = false");
    }

    @Test
    void crossNamespaceIdentityLookupExcludesOrphanedRows() throws Exception {
        Method method = IotDeviceRepository.class.getMethod(
                "findRegisteredBySourceScopedIdentifier", Long.class, String.class);

        assertThat(queryText(method))
                .contains("device.status = 'REGISTERED'")
                .contains("device.is_deleted = false")
                .contains("LIMIT 2");
    }

    @Test
    void syncPageUsesOneSourceScopedBulkLookup() throws Exception {
        Method method = IotDeviceRepository.class.getMethod(
                "findByDeviceSourceIdAndSourceDeviceIdInAndIsDeletedFalse",
                Long.class, Collection.class);

        assertThat(method.getReturnType()).isEqualTo(java.util.List.class);
    }

    @Test
    void staleDeviceLockRequiresAResultLimit() throws Exception {
        Method method = IotDeviceRepository.class.getMethod(
                "lockStaleDevices", Long.class, java.time.OffsetDateTime.class, Pageable.class);

        assertThat(queryText(method)).contains("ORDER BY d.id");
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
