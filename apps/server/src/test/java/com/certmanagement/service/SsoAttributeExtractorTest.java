// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.security.oidc.SsoConfig;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SsoAttributeExtractorTest {

    private SsoAttributeExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new SsoAttributeExtractor(JsonMapper.builderWithJackson2Defaults().build());
    }

    // ===== OIDC =====

    /**
     * Entra's OIDC {@code sub} is pairwise per application client ID, while {@code oid} is the
     * tenant-wide object ID. Storing oid keeps identity intact across a client-ID rotation or a new
     * app registration, which a pairwise sub would not survive.
     */
    @Test
    void oidc_prefersEntraOidWhenTenantIdAlsoPresent() {
        OidcUser u = mock(OidcUser.class);
        lenient().when(u.getSubject()).thenReturn("pairwise-sub");
        when(u.getClaims()).thenReturn(Map.of(
                "email", "o@acme.io",
                "oid", "00000000-0000-0000-0000-0000000000a1",
                "tid", "00000000-0000-0000-0000-000000000000"));

        assertThat(extractor.extractFromOidc(u, "reg-1").getIdpUserId())
                .isEqualTo("00000000-0000-0000-0000-0000000000a1");
    }

    /** A claim merely named "oid" from some other IdP carries no such promise — tid gates it. */
    @Test
    void oidc_usesSubWhenOidIsNotAccompaniedByTenantId() {
        OidcUser u = mock(OidcUser.class);
        when(u.getSubject()).thenReturn("sub-1");
        when(u.getClaims()).thenReturn(Map.of("email", "o@acme.io", "oid", "ambiguous"));

        assertThat(extractor.extractFromOidc(u, "reg-1").getIdpUserId()).isEqualTo("sub-1");
    }

    /**
     * Some IdPs expose a stable identifier only under a claim the customer chooses, so the
     * per-organization override ({@code userId} in the attribute mapping) wins outright.
     */
    @Test
    void oidc_configuredSubjectClaimWinsOverBuiltInCandidates() {
        OidcUser u = mock(OidcUser.class);
        lenient().when(u.getSubject()).thenReturn("pairwise-sub");
        when(u.getClaims()).thenReturn(Map.of(
                "oid", "entra-guid",
                "tid", "tenant-guid",
                "employeeId", "  E-1042  "));
        SsoConfig cfg = SsoConfig.builder()
                .attributeMapping("{\"userId\":\"employeeId\"}")
                .build();

        assertThat(extractor.extractFromOidc(u, "reg-1", cfg).getIdpUserId())
                .as("trimmed, never case-folded").isEqualTo("E-1042");
    }

    @Test
    void oidc_fallsBackWhenConfiguredSubjectClaimIsAbsent() {
        OidcUser u = mock(OidcUser.class);
        lenient().when(u.getSubject()).thenReturn("pairwise-sub");
        when(u.getClaims()).thenReturn(Map.of("oid", "entra-guid", "tid", "tenant-guid"));
        SsoConfig cfg = SsoConfig.builder()
                .attributeMapping("{\"userId\":\"neverSent\"}")
                .build();

        assertThat(extractor.extractFromOidc(u, "reg-1", cfg).getIdpUserId()).isEqualTo("entra-guid");
    }

    @Test
    void oidc_blankSubjectIsNoSubject() {
        OidcUser u = mock(OidcUser.class);
        when(u.getSubject()).thenReturn("   ");
        when(u.getClaims()).thenReturn(Map.of("email", "o@acme.io"));

        assertThat(extractor.extractFromOidc(u, "reg-1").getIdpUserId()).isNull();
    }

    private OidcUser oidcUser() {
        OidcUser u = mock(OidcUser.class);
        lenient().when(u.getSubject()).thenReturn("sub-1");
        lenient().when(u.getEmail()).thenReturn("o@acme.io");
        lenient().when(u.getGivenName()).thenReturn("Oid");
        lenient().when(u.getFamilyName()).thenReturn("User");
        lenient().when(u.getFullName()).thenReturn("Oid User");
        lenient().when(u.getClaims()).thenReturn(Map.of("email", "o@acme.io"));
        lenient().when(u.getAttributes()).thenReturn(Map.of(
                "groups", List.of("og1"),
                "roles", List.of("orole")));
        return u;
    }

    @Test
    void extractFromOidc_populatesAllFields() {
        SsoUserInfo info = extractor.extractFromOidc(oidcUser(), "azure");
        assertThat(info.getEmail()).isEqualTo("o@acme.io");
        assertThat(info.getIdpUserId()).isEqualTo("sub-1");
        assertThat(info.getFirstName()).isEqualTo("Oid");
        assertThat(info.getLastName()).isEqualTo("User");
        assertThat(info.getDisplayName()).isEqualTo("Oid User");
        assertThat(info.getGroups()).containsExactly("og1");
        assertThat(info.getRoles()).containsExactly("orole");
        assertThat(info.getAuthMethod()).isEqualTo("OIDC");
        assertThat(info.getOrganizationDomain()).isEqualTo("acme.io");
    }

    @Test
    void extractFromOidc_nullEmail_fallsBackToAttribute() {
        OidcUser u = mock(OidcUser.class);
        when(u.getSubject()).thenReturn("sub-2");
        when(u.getEmail()).thenReturn(null);
        when(u.getClaims()).thenReturn(Map.of());
        when(u.getAttributes()).thenReturn(Map.of("preferred_username", "pref@acme.io"));

        SsoUserInfo info = extractor.extractFromOidc(u, "azure");
        assertThat(info.getEmail()).isEqualTo("pref@acme.io");
    }

    @Test
    void extractFromOidc_withCustomClaims_overrides() {
        OidcUser u = oidcUser();
        when(u.getAttributes()).thenReturn(Map.of("appRoles", List.of("r1", "r2")));

        SsoConfig cfg = SsoConfig.builder().rolesClaimName("appRoles").build();

        SsoUserInfo info = extractor.extractFromOidc(u, "azure", cfg);
        assertThat(info.getRoles()).containsExactlyInAnyOrder("r1", "r2");
    }

    // ===== OAuth2 =====

    @Test
    void extractFromOAuth2_populatesFields() {
        OAuth2User u = mock(OAuth2User.class);
        when(u.getName()).thenReturn("oauth-name");
        when(u.getAttributes()).thenReturn(Map.of(
                "email", "oa@acme.io",
                "givenName", "OA",
                "surname", "Last",
                "groups", List.of("grpA")));

        SsoUserInfo info = extractor.extractFromOAuth2(u, "github");
        assertThat(info.getEmail()).isEqualTo("oa@acme.io");
        assertThat(info.getFirstName()).isEqualTo("OA");
        assertThat(info.getLastName()).isEqualTo("Last");
        assertThat(info.getGroups()).containsExactly("grpA");
        assertThat(info.getProvider()).isEqualTo("github");
    }

    @Test
    void extractFromOAuth2_noEmail_fallsBackToName() {
        OAuth2User u = mock(OAuth2User.class);
        when(u.getName()).thenReturn("just-name");
        when(u.getAttributes()).thenReturn(Map.of());
        SsoUserInfo info = extractor.extractFromOAuth2(u, "github");
        assertThat(info.getEmail()).isEqualTo("just-name");
    }

    @Test
    void extractFromOAuth2_withCustomConfig_overridesGroups() {
        OAuth2User u = mock(OAuth2User.class);
        lenient().when(u.getName()).thenReturn("n");
        when(u.getAttributes()).thenReturn(Map.of(
                "email", "x@acme.io",
                "teams", new String[]{"t1", "t2"}));

        SsoConfig cfg = SsoConfig.builder().groupsClaimName("teams").build();

        SsoUserInfo info = extractor.extractFromOAuth2(u, "github", cfg);
        assertThat(info.getGroups()).containsExactlyInAnyOrder("t1", "t2");
    }

    // ===== applyAttributeMapping =====

    @Test
    void applyAttributeMapping_blank_returnsUnchanged() {
        SsoUserInfo info = SsoUserInfo.builder().email("a@b.io").build();
        assertThat(extractor.applyAttributeMapping(info, "")).isSameAs(info);
        assertThat(extractor.applyAttributeMapping(info, null).getEmail()).isEqualTo("a@b.io");
    }

    @Test
    void applyAttributeMapping_remapsFields() {
        SsoUserInfo info = SsoUserInfo.builder()
                .email("old@b.io")
                .attributes(Map.of("custom_email", "new@b.io", "fn", "Bob", "ln", "Smith", "dn", "Bob S"))
                .build();

        String mapping = "{\"email\":\"custom_email\",\"firstName\":\"fn\",\"lastName\":\"ln\",\"displayName\":\"dn\"}";
        SsoUserInfo out = extractor.applyAttributeMapping(info, mapping);

        assertThat(out.getEmail()).isEqualTo("new@b.io");
        assertThat(out.getFirstName()).isEqualTo("Bob");
        assertThat(out.getLastName()).isEqualTo("Smith");
        assertThat(out.getDisplayName()).isEqualTo("Bob S");
    }

    @Test
    void applyAttributeMapping_invalidJson_returnsUnchanged() {
        SsoUserInfo info = SsoUserInfo.builder().email("old@b.io").build();
        SsoUserInfo out = extractor.applyAttributeMapping(info, "not-json");
        assertThat(out.getEmail()).isEqualTo("old@b.io");
    }
}
