// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Covers the remaining conditional branches in {@link CertificateEntity} derived getters
 * that the broader entity tests do not exercise.
 */
class EntityBranchCoverageTest {

    @Test
    void certificateEntity_derivedGetters_bothBranches() {
        // null navigation -> null
        CertificateEntity nullNav = CertificateEntity.builder().build();
        assertThat(nullNav.getDomain()).isNull();
        assertThat(nullNav.getOrganizationId()).isNull();

        // populated navigation -> delegates
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .domain("example.com")
                .organizationId(42L)
                .build();
        CertificateEntity withNav = CertificateEntity.builder().userDomainCert(udc).build();
        assertThat(withNav.getDomain()).isEqualTo("example.com");
        assertThat(withNav.getOrganizationId()).isEqualTo(42L);

        withNav.onCreate();
        assertThat(withNav.getCreatedAt()).isNotNull();
        assertThat(withNav.getUpdatedAt()).isNotNull();
        withNav.onUpdate();
        assertThat(withNav.getUpdatedAt()).isNotNull();
    }


}
