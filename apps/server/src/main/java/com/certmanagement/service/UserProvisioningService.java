// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.Role;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.entity.User;
import com.certmanagement.exception.SsoMemberNotProvisionedException;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.service.audit.AccessAuditRecorder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

/**
 * Service for Just-In-Time (JIT) user provisioning from SSO.
 * 
 * Supports two role management modes:
 * 1. LOCAL: Roles managed in application database (syncRolesOnFirstLogin = false)
 * 2. IDP-INITIAL: Roles synced from Identity Provider only on first login
 *    during JIT provisioning (syncRolesOnFirstLogin = true)
 * 
 * When syncRolesOnFirstLogin is enabled:
 * - Roles are extracted from OIDC tokens
 * - Role mapping translates IDP roles/groups to application roles
 * - Mapping is applied only while creating a new JIT-provisioned user
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserProvisioningService {

    private final UserRepository userRepository;
    private final RoleMappingService roleMappingService;
    private final AccessAuditRecorder accessAudit;

    /**
     * Find or create user based on SSO user info.
     * Implements JIT provisioning - creates user on first login if not exists.
     */
    public User findOrProvisionUser(SsoUserInfo userInfo, Organization organization, SsoConfig ssoConfig) {
        // First try to find by IdP user ID
        Optional<User> existingUser = userRepository.findByIdpUserIdAndOrganizationId(
            userInfo.getIdpUserId(), organization.getId()
        );

        if (existingUser.isPresent()) {
            return updateExistingUser(existingUser.get(), userInfo, ssoConfig);
        }

        // Then try by email, case-insensitively — uniqueness is enforced on LOWER(email), so an
        // assertion whose casing differs from the stored value still means the same person.
        existingUser = userRepository.findByEmailIgnoreCaseAndOrganizationId(
            userInfo.getEmail(), organization.getId()
        );

        if (existingUser.isPresent()) {
            User user = existingUser.get();
            linkIdpIdentity(user, userInfo);
            return updateExistingUser(user, userInfo, ssoConfig);
        }

        // Auto-provision new user if enabled
        if (Boolean.TRUE.equals(ssoConfig.getAutoProvisionEnabled())) {
            // Loud on purpose. Neither lookup matched, so this forks a second account for anyone
            // who already exists under a different address or a different IdP identifier — the
            // failure mode is invisible from the user's side, since their login simply succeeds.
            contextLogger().warn("No existing user matched for SSO login — provisioning a new account "
                    + "in organization {} (subject={}, registration={})",
                    organization.getId(), userInfo.getIdpUserId(), ssoConfig.getRegistrationId());
            return provisionNewUser(userInfo, organization, ssoConfig);
        }

        contextLogger().warn("User not found and auto-provisioning disabled for organization: {}", organization.getDomain());
        throw new SsoMemberNotProvisionedException("User not found and auto-provisioning is disabled");
    }

    /**
     * Attach the IdP's identifier to a user matched by email.
     *
     * <p>A stored identifier that differs from the asserted one means the IdP now presents this
     * person differently — an email-format NameID following a rename, or a move to a stable
     * attribute. Adopt the new value so the next login matches on the identifier rather than
     * falling back to email again, and record it, because the same shape of event would also be
     * produced by an IdP administrator pointing one user's identity at another's address.
     */
    private void linkIdpIdentity(User user, SsoUserInfo userInfo) {
        String asserted = userInfo.getIdpUserId();
        if (asserted == null || asserted.isBlank()) {
            return;
        }
        String stored = user.getIdpUserId();
        if (stored == null) {
            user.setIdpUserId(asserted);
            contextLogger().info("Linked IdP identity to existing user {}", user.getId());
        } else if (!stored.equals(asserted)) {
            contextLogger().warn("IdP identifier changed for user {} — re-linking to the asserted "
                    + "identity (matched by email)", user.getId());
            user.setIdpUserId(asserted);
        }
    }

    /**
     * Provision a new user from SSO.
     * 
     * Role assignment logic:
    * - If syncRolesOnFirstLogin is enabled: Map IDP roles/groups to application roles
    * - Otherwise: Assign the configured default role from SSO config
     */
    private User provisionNewUser(SsoUserInfo userInfo, Organization organization, SsoConfig ssoConfig) {
        contextLogger().info("Provisioning new user for organization: {}", organization.getDomain());

        // Determine roles based on sync mode
        Set<Role> roles;
        boolean mappedFromIdp = roleMappingService.shouldSyncRolesOnFirstLogin(ssoConfig);
        if (mappedFromIdp) {
            // Map IDP roles/groups to application roles
            roles = roleMappingService.mapIdpRolesToAppRoles(userInfo, ssoConfig);
            contextLogger().info("Mapped {} IDP roles/groups to {} application roles for new user", 
                userInfo.getRoles().size() + userInfo.getGroups().size(), roles.size());
        } else {
            // Use default role from SSO config
            roles = roleMappingService.getDefaultRole(ssoConfig);
        }

        User user = User.builder()
            .email(userInfo.getEmail())
            .organization(organization)
            .idpUserId(userInfo.getIdpUserId())
            .active(true)
            .provisionedAt(OffsetDateTime.now(ZoneOffset.UTC))
            .lastLoginAt(OffsetDateTime.now(ZoneOffset.UTC))
            .roles(roles)
            .build();

        User savedUser = userRepository.save(user);
        String source = mappedFromIdp ? "IDP_ROLE_MAPPING" : "DEFAULT_ROLE";
        accessAudit.ssoRolesAssigned(savedUser, roles, source, ssoConfig.getRegistrationId());
        contextLogger().info("Provisioned new user with ID: {} with {} role(s)", savedUser.getId(), roles.size());

        return savedUser;
    }

    /**
     * Update existing user on login.
     *
     * Role sync is intentionally not performed for existing users.
    * If syncRolesOnFirstLogin is enabled, mapping was already applied during
     * initial provisioning on the user's first login.
     */
    private User updateExistingUser(User user, SsoUserInfo userInfo, SsoConfig ssoConfig) {
        contextLogger().debug("Updating existing user");

        // Update last login
        user.setLastLoginAt(OffsetDateTime.now(ZoneOffset.UTC));

        return userRepository.save(user);
    }

    /**
     * Deactivate a user (e.g., when removed from IdP).
     */
    public void deactivateUser(Integer userId) {
        userRepository.findById(userId).ifPresent(user -> {
            user.disable();
            userRepository.save(user);
            accessAudit.memberDisabled(user, user.getRoles(), "SSO", AccessAuditRecorder.Actor.SSO_PROVISIONING);
            contextLogger().info("User deactivated");
        });
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(UserProvisioningService.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
