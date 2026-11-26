// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.audit.AuditScope;
import com.certmanagement.dto.organization.OrganizationDto;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.messaging.transport.AgentTokenService;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RoleRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.service.audit.AccessAuditRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.URI;
import java.util.List;
import java.util.Locale;

/**
 * Keeps a self-hosted install simple: the Platform Super Admin always works in an organization, so
 * the product's pages are there at the first sign-in instead of an almost empty sidebar.
 *
 * <p>For every super admin without an organization: with no organization yet, one is created
 * ({@code CERTPING_ORGANIZATION_NAME}, default "My organization") and the admin is put in it; with
 * exactly one, the admin is put in that one; with several, nothing happens and the admin picks one
 * ("Work in this organization"). Runs at startup and right after first-run setup. Never moves an
 * admin who already works in an organization.
 */
@Service
@Slf4j
public class FirstOrganizationService {

    static final String JOB = "first-organization";

    private final OrganizationRepository organizationRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final OrganizationService organizationService;
    private final AccessAuditRecorder accessAudit;
    private final ObjectProvider<AgentTokenService> agentTokens;
    private final TransactionTemplate transaction;
    private final String name;
    private final String domain;
    private final String baseUrl;

    public FirstOrganizationService(OrganizationRepository organizationRepository, UserRepository userRepository,
                                    RoleRepository roleRepository, OrganizationService organizationService, AccessAuditRecorder accessAudit,
                                    ObjectProvider<AgentTokenService> agentTokens,
                                    PlatformTransactionManager transactionManager,
                                    @Value("${certping.first-organization.name:My organization}") String name,
                                    @Value("${certping.first-organization.domain:}") String domain,
                                    @Value("${app.base-url:}") String baseUrl) {
        this.organizationRepository = organizationRepository;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.organizationService = organizationService;
        this.accessAudit = accessAudit;
        this.agentTokens = agentTokens;
        this.transaction = new TransactionTemplate(transactionManager);
        this.name = name == null || name.isBlank() ? "My organization" : name.trim();
        this.domain = domain;
        this.baseUrl = baseUrl;
    }

    /** Puts every super admin without an organization into one, creating it when there is none. */
    public void ensure() {
        List<User> admins = userRepository.findSuperAdminsWithoutOrganization();
        if (admins.isEmpty()) {
            return;
        }
        try (AuditScope scope = AuditScope.system(JOB, null)) {
            List<Organization> organizations = organizationRepository.findAll().stream()
                    .filter(org -> Boolean.TRUE.equals(org.getActive()))
                    .toList();
            if (organizations.size() > 1) {
                log.info("{} organizations exist: the Platform Super Admin chooses one to work in", organizations.size());
                return;
            }
            Long organizationId = organizations.isEmpty() ? create() : organizations.get(0).getId();
            transaction.executeWithoutResult(status -> {
                Organization organization = organizationRepository.findById(organizationId).orElseThrow();
                for (User admin : admins) {
                    User fresh = userRepository.findById(admin.getId()).orElseThrow();
                    if (fresh.getOrganization() != null) {
                        continue;
                    }
                    fresh.setOrganization(organization);
                    // SUPER_ADMIN is a platform role with no certificate permissions; the admin also
                    // administers the organization they work in, or its pages stay hidden.
                    roleRepository.findByNameAndOrganizationIsNull("ORGANIZATION_ADMIN")
                            .ifPresent(role -> fresh.getRoles().add(role));
                    userRepository.save(fresh);
                    accessAudit.memberOrganizationChanged(fresh);
                    log.info("Platform Super Admin '{}' works in organization '{}'", fresh.getUsername(),
                            organization.getName());
                }
            });
            // The bundled agent's token waits for the first organization; register it now.
            AgentTokenService tokens = agentTokens.getIfAvailable();
            if (tokens != null) {
                tokens.registerBootstrapToken();
            }
        } catch (RuntimeException e) {
            // Never stops the server: the admin can still create or choose an organization by hand.
            log.warn("Could not set up the first organization: {}", e.toString());
        }
    }

    private Long create() {
        OrganizationDto created = organizationService.createOrganization(OrganizationDto.builder()
                .name(name)
                .domain(organizationDomain())
                .active(true)
                .build());
        log.info("Created the first organization '{}' ({})", created.getName(), created.getId());
        return created.getId();
    }

    /** {@code certping.first-organization.domain}, else the host of the public URL, else certping.local. */
    String organizationDomain() {
        if (domain != null && !domain.isBlank()) {
            return domain.trim().toLowerCase(Locale.ROOT);
        }
        try {
            String host = baseUrl == null || baseUrl.isBlank() ? null : URI.create(baseUrl.trim()).getHost();
            if (host != null && !host.isBlank() && !host.equals("localhost") && !host.matches("[0-9.]+")) {
                return host.toLowerCase(Locale.ROOT);
            }
        } catch (IllegalArgumentException ignored) {
            // fall through
        }
        return "certping.local";
    }
}
