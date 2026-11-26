// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.organization.OrganizationDto;
import com.certmanagement.dto.organization.UpdateOrganizationRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.exception.DuplicateResourceException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.*;
import com.certmanagement.service.audit.OrganizationAuditRecorder;
import com.certmanagement.service.cbom.CertificateInventoryChangedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class OrganizationService {

    private final OrganizationRepository organizationRepository;
    private final OrganizationAuditRecorder organizationAudit;

    // cascade repositories
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserDomainCertRepository userDomainCertRepository;
    private final DomainCredentialConfigRepository domainCredentialConfigRepository;
    private final CertificateRepository certificateRepository;
    private final CertificateEventRepository certificateEventRepository;
    private final CertDeploymentConfigRepository certDeploymentConfigRepository;
    private final CredentialReferenceRepository credentialReferenceRepository;
    private final AlertRepository alertRepository;
    private final DeploymentRepository deploymentRepository;
    private final CertManualIssuanceStateRepository certManualIssuanceStateRepository;
    private final RenewalScheduleRepository renewalScheduleRepository;
    private final OrganizationFeatureFlagRepository organizationFeatureFlagRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final PlatformTransactionManager transactionManager;

    public OrganizationDto createOrganization(OrganizationDto dto) {
        if (organizationRepository.existsByDomain(dto.getDomain())) {
            throw new DuplicateResourceException("Organization with domain already exists: " + dto.getDomain());
        }
        if (organizationRepository.existsByName(dto.getName())) {
            throw new DuplicateResourceException("Organization with name already exists: " + dto.getName());
        }

        Organization organization = Organization.builder()
            .name(dto.getName())
            .domain(dto.getDomain())
            .slug(generateUniqueSlug(dto.getName()))
            .active(dto.getActive() != null ? dto.getActive() : true)
            .agentHeartbeatCadenceMinutes(
                dto.getAgentHeartbeatCadenceMinutes() != null ? dto.getAgentHeartbeatCadenceMinutes() : 5)
            .build();

        Organization saved = organizationRepository.save(organization);

        organizationAudit.organizationCreated(saved);

        contextLogger().info("Created organization: {} ({})", saved.getName(), saved.getId());
        return mapToDto(saved);
    }

    @Transactional(readOnly = true)
    public OrganizationDto getOrganizationById(Long id) {
        Organization organization = organizationRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Organization not found: " + id));
        return mapToDto(organization);
    }

    @Transactional(readOnly = true)
    public OrganizationDto getOrganizationByDomain(String domain) {
        Organization organization = organizationRepository.findByDomain(domain)
            .orElseThrow(() -> new ResourceNotFoundException("Organization not found for domain: " + domain));
        return mapToDto(organization);
    }

    @Transactional(readOnly = true)
    public OrganizationDto getOrganizationBySlug(String slug) {
        Organization organization = organizationRepository.findBySlug(slug)
            .orElseThrow(() -> new ResourceNotFoundException("Organization not found for slug: " + slug));
        return mapToDto(organization);
    }

    @Transactional(readOnly = true)
    public OrganizationDto getOrganizationByName(String name) {
        Organization organization = organizationRepository.findByName(name)
            .orElseThrow(() -> new ResourceNotFoundException("Organization not found with name: " + name));
        return mapToDto(organization);
    }

    @Transactional(readOnly = true)
    public List<OrganizationDto> getAllOrganizations() {
        return organizationRepository.findAll(Sort.by(Sort.Direction.DESC, "updatedAt")).stream()
            .map(this::mapToDto)
            .collect(Collectors.toList());
    }

    public OrganizationDto updateOrganization(Long id, UpdateOrganizationRequest request) {
        Organization existing = organizationRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Organization not found: " + id));

        String domainBefore = existing.getDomain();
        Boolean activeBefore = existing.getActive();
        boolean renamed = false;

        if (request.getName() != null && !request.getName().equals(existing.getName())) {
            if (organizationRepository.existsByNameAndIdNot(request.getName(), id)) {
                throw new DuplicateResourceException("Organization with name already exists: " + request.getName());
            }
            existing.setName(request.getName());
            renamed = true;
        }

        if (request.getDomain() != null && !request.getDomain().equals(existing.getDomain())) {
            if (organizationRepository.existsByDomainAndIdNot(request.getDomain(), id)) {
                throw new DuplicateResourceException("Organization with domain already exists: " + request.getDomain());
            }
            existing.setDomain(request.getDomain());
        }

        if (request.getActive() != null && !request.getActive().equals(existing.getActive())) {
            existing.setActive(request.getActive());
        }

        Organization updated = organizationRepository.save(existing);

        organizationAudit.organizationUpdated(id, renamed, domainBefore, updated.getDomain(), activeBefore,
            updated.getActive());

        contextLogger().info("Updated organization: {}", id);
        return mapToDto(updated);
    }

    /** Deletes the organization and its data in one transaction. */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void deleteOrganization(Long id) {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> deleteOrganizationData(id));
    }

    /**
     * Locks the organization row before touching any user, the order the last-admin guard in
     * {@code PermissionGrantPolicy} takes too, so a delete and a concurrent demotion queue instead
     * of deadlocking.
     */
    private void deleteOrganizationData(Long id) {
        Organization organization = organizationRepository.findByIdForUpdate(id)
            .orElseThrow(() -> new ResourceNotFoundException("Organization not found: " + id));

        // Cascade soft-delete: cert-level data first (leaf → parent order). Bulk-flips
        // is_deleted on every child table the single-cert delete path touches, so org
        // delete leaves no stale rows behind for the @Where(is_deleted=false) filters.
        certManualIssuanceStateRepository.softDeleteByOrganizationId(id);
        certificateEventRepository.softDeleteByOrganizationId(id);
        renewalScheduleRepository.softDeleteByOrganizationId(id);
        certDeploymentConfigRepository.softDeleteByOrganizationId(id);
        deploymentRepository.softDeleteByOrganizationId(id);
        certificateRepository.softDeleteAllByOrganizationId(id);
        domainCredentialConfigRepository.softDeleteByOrganizationId(id);
        userDomainCertRepository.softDeleteByOrganizationId(id);
        eventPublisher.publishEvent(new CertificateInventoryChangedEvent());

        // Credential references, alerts, feature flags
        credentialReferenceRepository.softDeleteByOrganizationId(id);
        alertRepository.softDeleteByOrganizationId(id);
        organizationFeatureFlagRepository.softDeleteAllByOrganizationId(id);

        // Users and their join tables
        userRepository.softDeleteUserRolesByOrganizationId(id);
        userRepository.softDeleteUserPermissionsByOrganizationId(id);
        userRepository.softDeleteByOrganizationId(id);

        // Roles (custom only) and their permission assignments
        List<Long> customRoleIds = roleRepository.findCustomRoleIdsByOrganizationId(id);
        for (Long roleId : customRoleIds) {
            roleRepository.softDeleteRolePermissionsByRoleId(roleId);
        }
        roleRepository.softDeleteCustomRolesByOrganizationId(id);

        organization.setIsDeleted(true);
        organization.setActive(false);
        organizationRepository.save(organization);

        organizationAudit.organizationDeleted(id);

        contextLogger().info("Soft-deleted organization and all related entities: {}", id);
    }

    private OrganizationDto mapToDto(Organization organization) {
        return OrganizationDto.builder()
            .id(organization.getId())
            .name(organization.getName())
            .domain(organization.getDomain())
            .slug(organization.getSlug())
            .active(organization.getActive())
            .orgType(organization.getOrgType())
            .agentHeartbeatCadenceMinutes(organization.getAgentHeartbeatCadenceMinutes())
            .softDeleteRetentionDays(organization.getSoftDeleteRetentionDays())
            .createdAt(organization.getCreatedAt())
            .updatedAt(organization.getUpdatedAt())
            .build();
    }

    private String generateUniqueSlug(String organizationName) {
        String baseSlug = slugify(organizationName);
        if (!organizationRepository.existsBySlug(baseSlug)) {
            return baseSlug;
        }

        int suffix = 2;
        while (organizationRepository.existsBySlug(baseSlug + "-" + suffix)) {
            suffix++;
        }
        return baseSlug + "-" + suffix;
    }

    private String slugify(String input) {
        String normalized = input == null ? "" : input.trim().toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("^-+|-+$", "")
                .replaceAll("-+", "-");
        return normalized.isBlank() ? "organization" : normalized;
    }

    private Logger contextLogger() {
        return RequestContextLogger.getLogger(OrganizationService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
