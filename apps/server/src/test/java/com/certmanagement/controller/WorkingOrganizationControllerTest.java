// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.audit.AccessAuditRecorder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class WorkingOrganizationControllerTest {

    private final UserRepository users = mock(UserRepository.class);
    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private final AccessAuditRecorder audit = mock(AccessAuditRecorder.class);
    private final com.certmanagement.repository.RoleRepository roles = mock(com.certmanagement.repository.RoleRepository.class);
    private final com.certmanagement.security.JwtTokenProvider jwt = mock(com.certmanagement.security.JwtTokenProvider.class);
    private final com.certmanagement.service.RefreshTokenService refreshTokens =
            mock(com.certmanagement.service.RefreshTokenService.class);
    private final WorkingOrganizationController controller =
            new WorkingOrganizationController(users, organizations, roles, audit, jwt, refreshTokens);
    private User admin;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(1, null, "req", "admin@example.com");
        admin = User.builder().id(1).username("admin").email("admin@example.com")
                .roles(new java.util.HashSet<>()).build();
        when(users.findById(1)).thenReturn(Optional.of(admin));
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void choosingAnOrganizationSetsItOnTheAccountAndAuditsIt() {
        Organization acme = Organization.builder().id(7L).name("Acme").active(true).isDeleted(false).build();
        when(organizations.findById(7L)).thenReturn(Optional.of(acme));

        var body = controller.choose(new WorkingOrganizationController.WorkingOrganizationRequest(7L)).getBody();

        assertThat(admin.getOrganization()).isSameAs(acme);
        verify(users).save(admin);
        verify(audit).memberOrganizationChanged(admin);
        assertThat(body).containsEntry("organizationId", 7L).containsEntry("organizationName", "Acme");
    }

    @Test
    void choosingAnOrganizationAnswersWithTokensForIt() {
        Organization acme = Organization.builder().id(7L).name("Acme").active(true).isDeleted(false).build();
        when(organizations.findById(7L)).thenReturn(Optional.of(acme));
        admin.setAuthMethod(User.AuthMethod.LOCAL);
        when(jwt.generateAccessToken(admin, acme, "LOCAL")).thenReturn("access-7");
        when(jwt.generateRefreshToken(admin, acme)).thenReturn("refresh-7");

        var body = controller.choose(new WorkingOrganizationController.WorkingOrganizationRequest(7L)).getBody();

        assertThat(body).containsEntry("accessToken", "access-7").containsEntry("refreshToken", "refresh-7");
        verify(refreshTokens).recordIssued("refresh-7", admin, "LOCAL");
    }

    @Test
    void choosingTheSameOrganizationAgainChangesNothing() {
        Organization acme = Organization.builder().id(7L).name("Acme").active(true).isDeleted(false).build();
        admin.setOrganization(acme);
        when(organizations.findById(7L)).thenReturn(Optional.of(acme));

        controller.choose(new WorkingOrganizationController.WorkingOrganizationRequest(7L));

        verify(users, never()).save(any());
        verify(audit, never()).memberOrganizationChanged(any());
    }

    @Test
    void aDisabledOrDeletedOrganizationIsRefused() {
        when(organizations.findById(8L)).thenReturn(Optional.of(
                Organization.builder().id(8L).name("Off").active(false).isDeleted(false).build()));
        when(organizations.findById(9L)).thenReturn(Optional.of(
                Organization.builder().id(9L).name("Gone").active(true).isDeleted(true).build()));

        assertThatThrownBy(() -> controller.choose(new WorkingOrganizationController.WorkingOrganizationRequest(8L)))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> controller.choose(new WorkingOrganizationController.WorkingOrganizationRequest(9L)))
                .isInstanceOf(ResourceNotFoundException.class);
        assertThatThrownBy(() -> controller.choose(new WorkingOrganizationController.WorkingOrganizationRequest(null)))
                .isInstanceOf(BadRequestException.class);
        verify(users, never()).save(any());
    }
}
