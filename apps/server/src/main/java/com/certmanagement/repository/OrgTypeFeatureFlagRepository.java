// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.OrgTypeFeatureFlag;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrgTypeFeatureFlagRepository extends JpaRepository<OrgTypeFeatureFlag, Long> {

    Optional<OrgTypeFeatureFlag> findByOrgTypeAndFeatureKey(String orgType, String featureKey);

    interface EnabledView {
        Boolean getEnabled();
    }

    @Query("SELECT o.enabled AS enabled FROM OrgTypeFeatureFlag o "
            + "WHERE o.orgType = :orgType AND o.featureKey = :featureKey")
    Optional<EnabledView> findEnabledByOrgTypeAndFeatureKey(@Param("orgType") String orgType,
                                                            @Param("featureKey") String featureKey);

    List<OrgTypeFeatureFlag> findAllByOrgType(String orgType);

    /** One flag's defaults for every org type: at most one row per type. */
    List<OrgTypeFeatureFlag> findAllByFeatureKey(String featureKey);

    @Modifying
    @Query("DELETE FROM OrgTypeFeatureFlag o WHERE o.orgType = :orgType AND o.featureKey = :featureKey")
    int deleteByOrgTypeAndFeatureKey(@Param("orgType") String orgType,
                                     @Param("featureKey") String featureKey);
}
