// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.organization.OrganizationDto;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.messaging.transport.AgentTokenService;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.service.audit.AccessAuditRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class FirstOrganizationServiceTest {

    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private final UserRepository users = mock(UserRepository.class);
    private final com.certmanagement.repository.RoleRepository roles = mock(com.certmanagement.repository.RoleRepository.class);
    private final OrganizationService organizationService = mock(OrganizationService.class);
    private final AccessAuditRecorder audit = mock(AccessAuditRecorder.class);
    private final AgentTokenService agentTokens = mock(AgentTokenService.class);
    private User admin;

    @SuppressWarnings("unchecked")
    private FirstOrganizationService service(String domain, String baseUrl) {
        ObjectProvider<AgentTokenService> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(agentTokens);
        return new FirstOrganizationService(organizations, users, roles, organizationService, audit, provider,
                mock(PlatformTransactionManager.class), "Acme", domain, baseUrl);
    }

    @BeforeEach
    void setUp() {
        admin = User.builder().id(1).username("admin").email("admin@certping.local")
                .roles(new java.util.HashSet<>()).build();
        when(roles.findByNameAndOrganizationIsNull("ORGANIZATION_ADMIN")).thenReturn(Optional.of(
                com.certmanagement.entity.Role.builder().id(2L).name("ORGANIZATION_ADMIN").build()));
        when(users.findById(1)).thenReturn(Optional.of(admin));
    }

    @Test
    void withNoOrganizationOneIsCreatedAndTheAdminWorksInIt() {
        when(users.findSuperAdminsWithoutOrganization()).thenReturn(List.of(admin));
        when(organizations.findAll()).thenReturn(List.of());
        Organization acme = Organization.builder().id(5L).name("Acme").active(true).build();
        when(organizationService.createOrganization(any())).thenReturn(OrganizationDto.builder().id(5L).name("Acme").build());
        when(organizations.findById(5L)).thenReturn(Optional.of(acme));

        service("", "https://certping.example.com").ensure();

        verify(organizationService).createOrganization(org.mockito.ArgumentMatchers.argThat(dto ->
                dto.getName().equals("Acme") && dto.getDomain().equals("certping.example.com")));
        assertThat(admin.getOrganization()).isSameAs(acme);
        assertThat(admin.getRoleNames()).contains("ORGANIZATION_ADMIN");
        verify(users).save(admin);
        verify(audit).memberOrganizationChanged(admin);
        verify(agentTokens).registerBootstrapToken();
    }

    @Test
    void withExactlyOneOrganizationTheAdminIsPutInIt() {
        Organization only = Organization.builder().id(3L).name("Only").active(true).build();
        when(users.findSuperAdminsWithoutOrganization()).thenReturn(List.of(admin));
        when(organizations.findAll()).thenReturn(List.of(only));
        when(organizations.findById(3L)).thenReturn(Optional.of(only));

        service("", "").ensure();

        verify(organizationService, never()).createOrganization(any());
        assertThat(admin.getOrganization()).isSameAs(only);
    }

    @Test
    void withSeveralOrganizationsOrNoAdminToPlaceNothingChanges() {
        when(users.findSuperAdminsWithoutOrganization()).thenReturn(List.of(admin));
        when(organizations.findAll()).thenReturn(List.of(
                Organization.builder().id(3L).active(true).build(), Organization.builder().id(4L).active(true).build()));
        service("", "").ensure();
        assertThat(admin.getOrganization()).isNull();

        when(users.findSuperAdminsWithoutOrganization()).thenReturn(List.of());
        service("", "").ensure();
        verify(organizationService, never()).createOrganization(any());
        verify(users, never()).save(any());
    }

    @Test
    void theDomainComesFromTheSettingThenThePublicUrlThenADefault() {
        assertThat(service("Example.ORG", "https://x.test").organizationDomain()).isEqualTo("example.org");
        assertThat(service("", "https://certping.acme.test:8443").organizationDomain()).isEqualTo("certping.acme.test");
        assertThat(service("", "http://localhost:8088").organizationDomain()).isEqualTo("certping.local");
        assertThat(service("", "http://127.0.0.1").organizationDomain()).isEqualTo("certping.local");
        assertThat(service(null, null).organizationDomain()).isEqualTo("certping.local");
    }
}
