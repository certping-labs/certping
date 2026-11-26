// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SsoUserInfoCoverageTest {

    @Test
    void getFullNamePrefersDisplayName() {
        SsoUserInfo u = SsoUserInfo.builder().displayName("Jane Doe").build();
        assertThat(u.getFullName()).isEqualTo("Jane Doe");
    }

    @Test
    void getFullNameFallsBackToFirstLast() {
        SsoUserInfo u = SsoUserInfo.builder().firstName("Jane").lastName("Doe").build();
        assertThat(u.getFullName()).isEqualTo("Jane Doe");

        SsoUserInfo blankDisplay = SsoUserInfo.builder().displayName("  ").firstName("A").lastName("B").build();
        assertThat(blankDisplay.getFullName()).isEqualTo("A B");
    }

    @Test
    void getFullNameFallsBackToEmail() {
        SsoUserInfo u = SsoUserInfo.builder().email("a@b.com").build();
        assertThat(u.getFullName()).isEqualTo("a@b.com");
    }

    @Test
    void buildersAndSetters() {
        SsoUserInfo u = SsoUserInfo.builder()
                .email("a@b.com")
                .idpUserId("idp")
                .groups(Set.of("g1"))
                .roles(Set.of("r1"))
                .attributes(Map.of("k", "v"))
                .authMethod("OIDC")
                .provider("reg")
                .organizationDomain("acme.com")
                .build();
        assertThat(u.getEmail()).isEqualTo("a@b.com");
        assertThat(u.getIdpUserId()).isEqualTo("idp");
        assertThat(u.getGroups()).containsExactly("g1");
        assertThat(u.getRoles()).containsExactly("r1");
        assertThat(u.getAttributes()).containsEntry("k", "v");
        assertThat(u.getAuthMethod()).isEqualTo("OIDC");
        assertThat(u.getProvider()).isEqualTo("reg");
        assertThat(u.getOrganizationDomain()).isEqualTo("acme.com");

        SsoUserInfo empty = new SsoUserInfo();
        empty.setFirstName("X");
        assertThat(empty.getFirstName()).isEqualTo("X");
        assertThat(u.toString()).contains("a@b.com");
    }
}
