// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DiscoveredCertEntity;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.jpa.domain.Specification;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class SpecificationsCoverageTest {

    @SuppressWarnings("unchecked")
    private CriteriaBuilder mockCb() {
        CriteriaBuilder cb = mock(CriteriaBuilder.class);
        Predicate p = mock(Predicate.class);
        lenient().when(cb.equal(any(), any())).thenReturn(p);
        lenient().when(cb.equal(any(), anyString())).thenReturn(p);
        lenient().when(cb.like(any(), anyString())).thenReturn(p);
        lenient().when(cb.lower(any())).thenReturn(mock(jakarta.persistence.criteria.Expression.class));
        lenient().when(cb.greaterThanOrEqualTo(any(), any(OffsetDateTime.class))).thenReturn(p);
        lenient().when(cb.lessThanOrEqualTo(any(), any(OffsetDateTime.class))).thenReturn(p);
        lenient().when(cb.desc(any())).thenReturn(mock(Order.class));
        lenient().when(cb.and(any(Predicate[].class))).thenReturn(p);
        return cb;
    }

    @SuppressWarnings("unchecked")
    private Root<?> mockRoot() {
        Root<?> root = mock(Root.class);
        Path path = mock(Path.class);
        lenient().when(root.get(anyString())).thenReturn(path);
        lenient().when(path.get(anyString())).thenReturn(path);
        return root;
    }

    @Test
    @SuppressWarnings("unchecked")
    void discoveredCertSpecAllFilters() {
        OffsetDateTime now = OffsetDateTime.now();
        Specification<DiscoveredCertEntity> spec = DiscoveredCertSpec.filter(
                1L, true, "example", "AWS_ACM", "RSA_2048", "ISSUED", now, now);
        Predicate result = spec.toPredicate((Root<DiscoveredCertEntity>) mockRoot(),
                mock(CriteriaQuery.class), mockCb());
        assertThat(result).isNotNull();

        // null/blank path
        Specification<DiscoveredCertEntity> sparse = DiscoveredCertSpec.filter(
                1L, null, "  ", "", "", "", null, null);
        Predicate sparseResult = sparse.toPredicate((Root<DiscoveredCertEntity>) mockRoot(),
                mock(CriteriaQuery.class), mockCb());
        assertThat(sparseResult).isNotNull();
    }
}
