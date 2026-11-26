// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.UserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserControllerTest {

    @Mock private UserService userService;

    @AfterEach
    void cleanupContext() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void getAllUsers_superAdminWithoutOrganizationIdUsesGlobalRead() {
        UserController controller = new UserController(userService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));

        controller.getAllUsers(null);

        verify(userService).getAllUsers();
    }

    @Test
    void getUserById_superAdminWithoutOrganizationIdUsesGlobalRead() {
        UserController controller = new UserController(userService);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));

        controller.getUserById(101, null);

        verify(userService).getUserById(101);
    }

    @Test
    void getAllUsers_organizationCallerCannotOverrideOrganization() {
        UserController controller = new UserController(userService);
        Long jwtOrganizationId = 1L;
        Long otherOrganizationId = 2L;
        GatewayRequestContext.set(10, String.valueOf(jwtOrganizationId), "req-1", "organization-admin@acme.com");

        assertThatThrownBy(() -> controller.getAllUsers(otherOrganizationId))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("organizationId override");
    }

    @Test
    void deleteUser_usesOrganizationScopedSoftDeletePath() {
        UserController controller = new UserController(userService);
        Long jwtOrganizationId = 11L;
        Integer userId = 42;
        GatewayRequestContext.set(10, String.valueOf(jwtOrganizationId), "req-1", "organization-admin@acme.com");

        controller.deleteUser(userId, null);

        verify(userService).deleteUserForOrganization(userId, jwtOrganizationId);
    }

    @Test
    void deleteUser_superAdminWithoutOrganizationIdUsesGlobalSoftDeletePath() {
        UserController controller = new UserController(userService);
        Integer userId = 77;
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        "super-admin", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));

        controller.deleteUser(userId, null);

        verify(userService).deleteUser(userId);
    }
}
