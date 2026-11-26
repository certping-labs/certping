// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.domain;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IntegrationRepository extends JpaRepository<Integration, Long> {

    boolean existsByOrganizationIdAndProviderAndDeletedAtIsNull(Long organizationId, IntegrationProvider provider);

    Optional<Integration> findByIdAndOrganizationIdAndDeletedAtIsNull(Long id, Long organizationId);

    Optional<Integration> findByOrganizationIdAndProviderAndDeletedAtIsNull(Long organizationId, IntegrationProvider provider);

    List<Integration> findAllByOrganizationIdAndDeletedAtIsNullOrderByProviderAsc(Long organizationId);

    List<Integration> findAllByOrganizationIdAndProviderInAndDeletedAtIsNull(
            Long organizationId, Set<IntegrationProvider> providers);
}
