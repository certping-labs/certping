// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.user.UserDto;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.UserService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserControllerMoreTest {

    @Mock private UserService userService;

    private UserController controller;

    private static final Long ORG_ID = 7L;

    @BeforeEach
    void setUp() {
        controller = new UserController(userService);
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
        SecurityContextHolder.clearContext();
    }

    private void asSuperAdmin() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("super", "n/a", List.of(() -> "ROLE_SUPER_ADMIN")));
    }

    private void asOrgUser() {
        GatewayRequestContext.set(1, String.valueOf(ORG_ID), "req-1", "user@example.com");
    }

    // ── getUserById org-scoped ────────────────────────────────────────

    @Test
    void getUserById_orgUser_usesOrgScopedLookup() {
        asOrgUser();
        UserDto dto = new UserDto();
        when(userService.getUserByIdAndOrganization(5, ORG_ID)).thenReturn(dto);

        assertThat(controller.getUserById(5, null).getBody()).isEqualTo(dto);
    }

    // ── getUsersForOrganization ───────────────────────────────────────

    @Test
    void getUsersForOrganization_superAdmin_returnsAllUsers() {
        asSuperAdmin();
        List<UserDto> users = List.of(new UserDto());
        when(userService.getAllUsers()).thenReturn(users);

        assertThat(controller.getUsersForOrganization(null).getBody()).isEqualTo(users);
    }

    @Test
    void getUsersForOrganization_orgUser_returnsOrgUsers() {
        asOrgUser();
        List<UserDto> users = List.of(new UserDto());
        when(userService.getUsersByOrganization(ORG_ID)).thenReturn(users);

        assertThat(controller.getUsersForOrganization(null).getBody()).isEqualTo(users);
    }

    // ── updateUser ────────────────────────────────────────────────────

    @Test
    void updateUser_superAdmin_usesGlobalUpdate() {
        asSuperAdmin();
        UserDto dto = new UserDto();
        when(userService.updateUser(5, dto)).thenReturn(dto);

        assertThat(controller.updateUser(5, null, dto).getBody()).isEqualTo(dto);
    }

    @Test
    void updateUser_orgUser_usesOrgScopedUpdate() {
        asOrgUser();
        UserDto dto = new UserDto();
        when(userService.updateUserForOrganization(5, ORG_ID, dto)).thenReturn(dto);

        assertThat(controller.updateUser(5, null, dto).getBody()).isEqualTo(dto);
    }

    @Test
    void updateUserForOrganization_orgUser_delegates() {
        asOrgUser();
        UserDto dto = new UserDto();
        when(userService.updateUserForOrganization(5, ORG_ID, dto)).thenReturn(dto);

        assertThat(controller.updateUserForOrganization(5, null, dto).getBody()).isEqualTo(dto);
    }

    // ── deleteUserForOrganization ─────────────────────────────────────

    @Test
    void deleteUserForOrganization_orgUser_delegates() {
        asOrgUser();

        ResponseEntity<Void> resp = controller.deleteUserForOrganization(5, null);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(userService).deleteUserForOrganization(5, ORG_ID);
    }

    @Test
    void deleteUserForOrganization_superAdmin_usesGlobalDelete() {
        asSuperAdmin();

        controller.deleteUserForOrganization(5, null);

        verify(userService).deleteUser(5);
    }

    // ── disableUser ───────────────────────────────────────────────────

    @Test
    void disableUser_superAdmin_usesGlobalDisable() {
        asSuperAdmin();

        controller.disableUser(5, null);

        verify(userService).disableUser(5);
    }

    @Test
    void disableUser_orgUser_usesOrgScopedDisable() {
        asOrgUser();

        controller.disableUser(5, null);

        verify(userService).disableUserForOrganization(5, ORG_ID);
    }

    @Test
    void disableUserForOrganization_orgUser_delegates() {
        asOrgUser();

        ResponseEntity<Void> resp = controller.disableUserForOrganization(5, null);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        verify(userService).disableUserForOrganization(5, ORG_ID);
    }
}
