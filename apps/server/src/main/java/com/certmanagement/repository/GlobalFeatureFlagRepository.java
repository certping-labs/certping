// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.GlobalFeatureFlag;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface GlobalFeatureFlagRepository extends JpaRepository<GlobalFeatureFlag, Long> {

    Optional<GlobalFeatureFlag> findByFeatureKey(String featureKey);

    interface ResolutionView {
        Boolean getEnabled();
        String getCategory();
        String getScope();
    }

    /** Scalar read: bypasses the persistence context, so it never returns a stale managed instance. */
    @Query("SELECT g.enabled AS enabled, g.category AS category, g.scope AS scope "
            + "FROM GlobalFeatureFlag g WHERE g.featureKey = :featureKey")
    Optional<ResolutionView> findResolutionViewByFeatureKey(@Param("featureKey") String featureKey);
}
