// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.inOrder;
import org.mockito.InOrder;
import com.certmanagement.dto.organization.OrganizationDto;
import com.certmanagement.dto.organization.UpdateOrganizationRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.repository.*;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OrganizationServiceTest {

    @Mock private OrganizationRepository organizationRepository;
    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private UserDomainCertRepository userDomainCertRepository;
    @Mock private DomainCredentialConfigRepository domainCredentialConfigRepository;
    @Mock private CertificateRepository certificateRepository;
    @Mock private CertificateEventRepository certificateEventRepository;
    @Mock private CertDeploymentConfigRepository certDeploymentConfigRepository;
    @Mock private CredentialReferenceRepository credentialReferenceRepository;
    @Mock private AlertRepository alertRepository;
    @Mock private DeploymentRepository deploymentRepository;
    @Mock private CertManualIssuanceStateRepository certManualIssuanceStateRepository;
    @Mock private RenewalScheduleRepository renewalScheduleRepository;
    @Mock private OrganizationFeatureFlagRepository organizationFeatureFlagRepository;
    @Mock private org.springframework.context.ApplicationEventPublisher eventPublisher;
    // Unstubbed, it has no check: B2B, where no domain service is configured.
    // A mock runs the delete's TransactionTemplate body; the tests check when the transaction starts.
    @Mock private PlatformTransactionManager transactionManager;

    @Mock private com.certmanagement.service.audit.OrganizationAuditRecorder organizationAuditRecorder;

    @InjectMocks
    private OrganizationService organizationService;

    // ── createOrganization ──────────────────────────────────────────────────

    @Test
    void createOrganization_throwsWhenDomainAlreadyExists() {
        when(organizationRepository.existsByDomain("acme.com")).thenReturn(true);
        OrganizationDto dto = OrganizationDto.builder().name("Acme").domain("acme.com").build();

        assertThatThrownBy(() -> organizationService.createOrganization(dto))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("domain");
    }

    @Test
    void createOrganization_throwsWhenNameAlreadyExists() {
        when(organizationRepository.existsByDomain("acme.com")).thenReturn(false);
        when(organizationRepository.existsByName("Acme")).thenReturn(true);
        OrganizationDto dto = OrganizationDto.builder().name("Acme").domain("acme.com").build();

        assertThatThrownBy(() -> organizationService.createOrganization(dto))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("name");
    }

    @Test
    void createOrganization_defaultsActiveToTrueAndHeartbeatTo5() {
        when(organizationRepository.existsByDomain(any())).thenReturn(false);
        when(organizationRepository.existsByName(any())).thenReturn(false);
        when(organizationRepository.existsBySlug(any())).thenReturn(false);
        Organization saved = organization(1L, "Acme", "acme.com", "acme");
        when(organizationRepository.save(any())).thenReturn(saved);

        OrganizationDto dto = OrganizationDto.builder().name("Acme").domain("acme.com").build();
        organizationService.createOrganization(dto);

        ArgumentCaptor<Organization> captor = ArgumentCaptor.forClass(Organization.class);
        verify(organizationRepository).save(captor.capture());
        assertThat(captor.getValue().getActive()).isTrue();
        assertThat(captor.getValue().getAgentHeartbeatCadenceMinutes()).isEqualTo(5);
    }

    // ── updateOrganization ──────────────────────────────────────────────────

    @Test
    void updateOrganization_throwsWhenOrgNotFound() {
        when(organizationRepository.findById(99L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> organizationService.updateOrganization(99L, new UpdateOrganizationRequest()))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void updateOrganization_throwsWhenNewNameTakenByDifferentOrg() {
        Organization existing = organization(1L, "Old", "old.com", "old");
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(organizationRepository.existsByNameAndIdNot("Taken", 1L)).thenReturn(true);

        UpdateOrganizationRequest req = new UpdateOrganizationRequest();
        req.setName("Taken");

        assertThatThrownBy(() -> organizationService.updateOrganization(1L, req))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("name");
    }

    @Test
    void updateOrganization_throwsWhenNewDomainTakenByDifferentOrg() {
        Organization existing = organization(1L, "Acme", "acme.com", "acme");
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(organizationRepository.existsByDomainAndIdNot("taken.com", 1L)).thenReturn(true);

        UpdateOrganizationRequest req = new UpdateOrganizationRequest();
        req.setDomain("taken.com");

        assertThatThrownBy(() -> organizationService.updateOrganization(1L, req))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("domain");
    }

    @Test
    void updateOrganization_allowsNoOpWhenSameNameAndDomain() {
        Organization existing = organization(1L, "Acme", "acme.com", "acme");
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(organizationRepository.save(any())).thenReturn(existing);

        UpdateOrganizationRequest req = new UpdateOrganizationRequest();
        req.setName("Acme");
        req.setDomain("acme.com");

        organizationService.updateOrganization(1L, req);

        // no uniqueness checks needed when value is unchanged
        verify(organizationRepository, never()).existsByNameAndIdNot(any(), any());
        verify(organizationRepository, never()).existsByDomainAndIdNot(any(), any());
    }

    @Test
    void updateOrganization_updatesFieldsAndPersists() {
        Organization existing = organization(1L, "Old Corp", "old.com", "old-corp");
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(organizationRepository.existsByNameAndIdNot("New Corp", 1L)).thenReturn(false);
        when(organizationRepository.existsByDomainAndIdNot("new.com", 1L)).thenReturn(false);
        when(organizationRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UpdateOrganizationRequest req = new UpdateOrganizationRequest();
        req.setName("New Corp");
        req.setDomain("new.com");
        req.setActive(false);
        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");

        OrganizationDto result = organizationService.updateOrganization(1L, req);

        assertThat(result.getName()).isEqualTo("New Corp");
        assertThat(result.getDomain()).isEqualTo("new.com");
        assertThat(result.getActive()).isFalse();
        // organization.updated: the rename by field name only, the domain and active flag with their values.
        verify(organizationAuditRecorder).organizationUpdated(eq(1L), eq(true), eq("old.com"), eq("new.com"),
                eq(Boolean.TRUE), eq(Boolean.FALSE));
    }

    @AfterEach
    void clearRequestContext() {
        RequestContextInterceptor.clearContext();
    }

    @Test
    void updateOrganization_leavesTheHeartbeatCadenceToItsOwnEndpoint() throws Exception {
        Organization existing = organization(1L, "Corp", "corp.com", "corp");
        existing.setAgentHeartbeatCadenceMinutes(5);
        when(organizationRepository.findById(1L)).thenReturn(Optional.of(existing));
        when(organizationRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        UpdateOrganizationRequest req = JsonMapper.builder().build()
                .readValue("{\"agentHeartbeatCadenceMinutes\":0}", UpdateOrganizationRequest.class);

        OrganizationDto result = organizationService.updateOrganization(1L, req);

        assertThat(result.getAgentHeartbeatCadenceMinutes()).isEqualTo(5);
        assertThat(existing.getAgentHeartbeatCadenceMinutes()).isEqualTo(5);
    }

    // ── deleteOrganization (cascade) ────────────────────────────────────────

    @Test
    void deleteOrganization_throwsWhenOrgNotFound() {
        when(organizationRepository.findByIdForUpdate(42L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> organizationService.deleteOrganization(42L))
                .isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void deleteOrganization_softDeletesCascadeToAllChildEntities() {
        Long orgId = 5L;
        Organization org = organization(orgId, "Acme", "acme.com", "acme");
        when(organizationRepository.findByIdForUpdate(orgId)).thenReturn(Optional.of(org));
        when(roleRepository.findCustomRoleIdsByOrganizationId(orgId)).thenReturn(Collections.emptyList());
        when(organizationRepository.save(any())).thenReturn(org);

        organizationService.deleteOrganization(orgId);

        verify(certManualIssuanceStateRepository).softDeleteByOrganizationId(orgId);
        verify(certificateEventRepository).softDeleteByOrganizationId(orgId);
        verify(renewalScheduleRepository).softDeleteByOrganizationId(orgId);
        verify(certDeploymentConfigRepository).softDeleteByOrganizationId(orgId);
        verify(eventPublisher).publishEvent(any(com.certmanagement.service.cbom.CertificateInventoryChangedEvent.class));
        verify(deploymentRepository).softDeleteByOrganizationId(orgId);
        verify(certificateRepository).softDeleteAllByOrganizationId(orgId);
        verify(domainCredentialConfigRepository).softDeleteByOrganizationId(orgId);
        verify(userDomainCertRepository).softDeleteByOrganizationId(orgId);
        verify(credentialReferenceRepository).softDeleteByOrganizationId(orgId);
        verify(alertRepository).softDeleteByOrganizationId(orgId);
        verify(organizationFeatureFlagRepository).softDeleteAllByOrganizationId(orgId);
        verify(userRepository).softDeleteUserRolesByOrganizationId(orgId);
        verify(userRepository).softDeleteUserPermissionsByOrganizationId(orgId);
        verify(userRepository).softDeleteByOrganizationId(orgId);
        verify(roleRepository).softDeleteCustomRolesByOrganizationId(orgId);
    }

    @Test
    void deleteOrganization_locksTheOrganizationRowBeforeTouchingAnyUser() {
        Long orgId = 5L;
        Organization org = organization(orgId, "Acme", "acme.com", "acme");
        when(organizationRepository.findByIdForUpdate(orgId)).thenReturn(Optional.of(org));
        when(roleRepository.findCustomRoleIdsByOrganizationId(orgId)).thenReturn(Collections.emptyList());
        when(organizationRepository.save(any())).thenReturn(org);

        organizationService.deleteOrganization(orgId);

        InOrder order = inOrder(organizationRepository, userRepository);
        order.verify(organizationRepository).findByIdForUpdate(orgId);
        order.verify(userRepository).softDeleteUserRolesByOrganizationId(orgId);
        order.verify(userRepository).softDeleteByOrganizationId(orgId);
        verify(organizationRepository, never()).findById(orgId);
    }

    @Test
    void deleteOrganization_deletesInItsOwnTransaction() {
        Long orgId = 5L;
        Organization org = organization(orgId, "Acme", "acme.com", "acme");
        when(organizationRepository.findByIdForUpdate(orgId)).thenReturn(Optional.of(org));
        when(roleRepository.findCustomRoleIdsByOrganizationId(orgId)).thenReturn(Collections.emptyList());
        when(organizationRepository.save(any())).thenReturn(org);

        organizationService.deleteOrganization(orgId);

        var order = inOrder(transactionManager, organizationRepository);
        order.verify(transactionManager).getTransaction(any());
        order.verify(organizationRepository).save(org);
        verify(userRepository).softDeleteByOrganizationId(orgId);
    }

    /** Overrides the class's @Transactional: the method opens its own transaction through a template. */
    @Test
    void deleteOrganization_runsOutsideTheClassTransaction() throws Exception {
        Transactional tx = OrganizationService.class.getMethod("deleteOrganization", Long.class).getAnnotation(Transactional.class);

        assertThat(tx).isNotNull();
        assertThat(tx.propagation()).isEqualTo(Propagation.NOT_SUPPORTED);
    }

    @Test
    void deleteOrganization_softDeletesRolePermissionsForEachCustomRole() {
        Long orgId = 5L;
        Organization org = organization(orgId, "Acme", "acme.com", "acme");
        when(organizationRepository.findByIdForUpdate(orgId)).thenReturn(Optional.of(org));
        when(roleRepository.findCustomRoleIdsByOrganizationId(orgId)).thenReturn(List.of(100L, 101L));
        when(organizationRepository.save(any())).thenReturn(org);

        organizationService.deleteOrganization(orgId);

        verify(roleRepository).softDeleteRolePermissionsByRoleId(100L);
        verify(roleRepository).softDeleteRolePermissionsByRoleId(101L);
    }

    @Test
    void deleteOrganization_setsIsDeletedAndActiveOnOrganizationEntity() {
        Long orgId = 5L;
        Organization org = organization(orgId, "Acme", "acme.com", "acme");
        org.setActive(true);
        org.setIsDeleted(false);
        when(organizationRepository.findByIdForUpdate(orgId)).thenReturn(Optional.of(org));
        when(roleRepository.findCustomRoleIdsByOrganizationId(orgId)).thenReturn(Collections.emptyList());
        when(organizationRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        organizationService.deleteOrganization(orgId);

        ArgumentCaptor<Organization> captor = ArgumentCaptor.forClass(Organization.class);
        verify(organizationRepository).save(captor.capture());
        assertThat(captor.getValue().getIsDeleted()).isTrue();
        assertThat(captor.getValue().getActive()).isFalse();
        // The domain service is told, once, and not per user of the organization.
    }

    @Test
    void deleteOrganization_marksTheOrganizationDeleted() {
        Long orgId = 5L;
        Organization org = organization(orgId, "Acme", "acme.com", "acme");
        when(organizationRepository.findByIdForUpdate(orgId)).thenReturn(Optional.of(org));
        when(roleRepository.findCustomRoleIdsByOrganizationId(orgId)).thenReturn(Collections.emptyList());
        when(organizationRepository.save(any())).thenReturn(org);
        organizationService.deleteOrganization(orgId);

        ArgumentCaptor<Organization> captor = ArgumentCaptor.forClass(Organization.class);
        verify(organizationRepository).save(captor.capture());
        assertThat(captor.getValue().getIsDeleted()).isTrue();
    }

    // ── getAllOrganizations ─────────────────────────────────────────────────

    @Test
    void getAllOrganizations_usesUpdatedAtDescendingSort() {
        when(organizationRepository.findAll(any(org.springframework.data.domain.Sort.class)))
                .thenReturn(Collections.emptyList());

        organizationService.getAllOrganizations();

        ArgumentCaptor<org.springframework.data.domain.Sort> sortCaptor =
                ArgumentCaptor.forClass(org.springframework.data.domain.Sort.class);
        verify(organizationRepository).findAll(sortCaptor.capture());
        org.springframework.data.domain.Sort.Order order = sortCaptor.getValue().getOrderFor("updatedAt");
        assertThat(order).isNotNull();
        assertThat(order.getDirection()).isEqualTo(org.springframework.data.domain.Sort.Direction.DESC);
    }

    // ── slug generation ─────────────────────────────────────────────────────

    @Test
    void createOrganization_generatesUniqueSlugFromName() {
        when(organizationRepository.existsByDomain("acme.example.com")).thenReturn(false);
        when(organizationRepository.existsByName("Acme Corp")).thenReturn(false);
        when(organizationRepository.existsBySlug("acme-corp")).thenReturn(false);
        when(organizationRepository.save(any())).thenAnswer(inv -> {
            Organization o = inv.getArgument(0);
            o.setId(42L);
            return o;
        });

        OrganizationDto result = organizationService.createOrganization(
                OrganizationDto.builder().name("Acme Corp").domain("acme.example.com").build());

        assertThat(result.getSlug()).isEqualTo("acme-corp");
    }

    @Test
    void createOrganization_appendsSuffixWhenSlugAlreadyExists() {
        when(organizationRepository.existsByDomain("acme2.example.com")).thenReturn(false);
        when(organizationRepository.existsByName("Acme Corp")).thenReturn(false);
        when(organizationRepository.existsBySlug("acme-corp")).thenReturn(true);
        when(organizationRepository.existsBySlug("acme-corp-2")).thenReturn(false);
        when(organizationRepository.save(any())).thenAnswer(inv -> {
            Organization o = inv.getArgument(0);
            o.setId(43L);
            return o;
        });

        OrganizationDto result = organizationService.createOrganization(
                OrganizationDto.builder().name("Acme Corp").domain("acme2.example.com").build());

        assertThat(result.getSlug()).isEqualTo("acme-corp-2");
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    private Organization organization(Long id, String name, String domain, String slug) {
        return Organization.builder()
                .id(id)
                .name(name)
                .domain(domain)
                .slug(slug)
                .active(true)
                .isDeleted(false)
                .agentHeartbeatCadenceMinutes(5)
                .build();
    }
}
