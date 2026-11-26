// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;


import com.certmanagement.dto.user.UserDto;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.AdminUserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.reflect.Method;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminControllerTest {

    @Mock private AdminUserService adminUserService;
    @Mock private OrganizationRepository organizationRepository;

    @AfterEach
    void cleanupGatewayContext() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }


    @Test
    void createUser_withoutOrganizationContext_throwsBadRequest() {
        AdminController controller = new AdminController(adminUserService, organizationRepository);
        com.certmanagement.dto.auth.CreateUserRequest request = com.certmanagement.dto.auth.CreateUserRequest.builder()
                .username("user1")
                .password("Password@12345")
                .email("user1@example.com")
                .build();

        GatewayRequestContext.clear();

        assertThatThrownBy(() -> controller.createUser(request))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Organization context is required");
    }

        @Test
        void createUser_superAdmin_usesOrganizationFromPayloadWithoutJwtContext() {
        AdminController controller = new AdminController(adminUserService, organizationRepository);
        Long organizationId = 7L;

        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken(
                "super-admin",
                "n/a",
                Set.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"))));

        com.certmanagement.dto.auth.CreateUserRequest request = com.certmanagement.dto.auth.CreateUserRequest.builder()
            .username("managed-user")
            .password("Password@12345")
            .email("managed-user@example.com")
            .displayName("Managed User")
            .organizationId(organizationId)
            .build();

        GatewayRequestContext.clear();

        Organization organization = Organization.builder().id(organizationId).name("Acme Corp").domain("acme.example").active(true).build();
        User created = User.builder()
            .id(99)
            .username("managed-user")
            .email("managed-user@example.com")
            .displayName("Managed User")
            .active(true)
            .roles(Set.of())
            .permissions(Set.of())
            .organization(organization)
            .build();

        when(organizationRepository.findById(organizationId)).thenReturn(Optional.of(organization));
        when(adminUserService.createUserFromRequest(request, organization)).thenReturn(created);

        ResponseEntity<UserDto> response = controller.createUser(request);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getOrganizationId()).isEqualTo(organizationId);
        assertThat(response.getBody().getOrganizationName()).isEqualTo("Acme Corp");
        assertThat(response.getBody().getUsername()).isEqualTo("managed-user");
        }

    @Test
    void createUser_organizationScopedCaller_ignoresPayloadOrganizationIdAndUsesJwtOrganization() {
        AdminController controller = new AdminController(adminUserService, organizationRepository);
        Long jwtOrganizationId = 11L;

        com.certmanagement.dto.auth.CreateUserRequest request = com.certmanagement.dto.auth.CreateUserRequest.builder()
                .username("user-jwt")
                .password("Password@12345")
                .email("user-jwt@example.com")
                .displayName("JWT User")
                .organizationId(999L)
                .build();

        GatewayRequestContext.set(1, String.valueOf(jwtOrganizationId), "req-1", "organization-admin@example.com");

        Organization organization = Organization.builder().id(jwtOrganizationId).name("JWT Organization").domain("jwt.example").active(true).build();
        User created = User.builder()
                .id(77)
                .username("user-jwt")
                .email("user-jwt@example.com")
                .displayName("JWT User")
                .active(true)
                .roles(Set.of())
                .permissions(Set.of())
                .organization(organization)
                .build();

        when(organizationRepository.findById(jwtOrganizationId)).thenReturn(Optional.of(organization));
        when(adminUserService.createUserFromRequest(request, organization)).thenReturn(created);

        ResponseEntity<UserDto> response = controller.createUser(request);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getOrganizationId()).isEqualTo(jwtOrganizationId);
        assertThat(response.getBody().getOrganizationName()).isEqualTo("JWT Organization");
    }
}
