// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.exception.RetryableNotificationException;
import com.certping.notification.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;
import java.util.function.Supplier;

/**
 * Maps roles (organization_admin, cert_manager, deployment_manager) to email addresses
 * via dynamic database lookups against the tables it shares with the server.
 *
 * Resolution strategy:
 * - Organization (organizationId present): Queries users with the specified roles in that organization.
 *   If no users found for any role, falls back to the requesting user's own email.
 * - User (organizationId null, userId present): Returns the user's own email directly.
 * - Platform (neither present): Resolves platform roles in {@link #PLATFORM_ROLES} to their
 *   active holders, for services that cannot read
 *   the users table to name the super admins itself. When no holder resolves, the bootstrap
 *   super-admin address (the server's {@code app.bootstrap-super-admin.email}) receives it, so
 *   a support alert is not dropped while the platform has no active super admin.
 * A lookup that fails is never "nobody": see {@link #lookUp}.
 */
@Service
@Slf4j
public class RoleEmailMapper {

    /** The platform roles a publisher may address; any other role without a context resolves to nobody. */
    static final Set<String> PLATFORM_ROLES = Set.of("SUPER_ADMIN");

    /** The server seeds the bootstrap super admin with this address when none is configured; nothing receives mail there. */
    static final String SEED_PLACEHOLDER_EMAIL = "super_admin@certping.local";

    static final String RECIPIENT_LOOKUP_FAILED = "RECIPIENT_LOOKUP_FAILED";

    /** A failed users query is usually a database blip or failover. */
    private static final Duration LOOKUP_RETRY_AFTER = Duration.ofMinutes(5);

    private final UserRepository userRepository;
    private final String bootstrapSuperAdminEmail;

    public RoleEmailMapper(UserRepository userRepository,
                           @Value("${app.bootstrap-super-admin.email:}") String bootstrapSuperAdminEmail) {
        this.userRepository = userRepository;
        this.bootstrapSuperAdminEmail = bootstrapSuperAdminEmail;
    }

    /** Whether these roles, with no organization or user, address platform-role holders. */
    static boolean addressesPlatformRole(List<String> roles, Long organizationId, Long userId) {
        if (roles == null || organizationId != null || userId != null) {
            return false;
        }
        return roles.stream().anyMatch(role -> role != null && PLATFORM_ROLES.contains(platformRoleName(role)));
    }

    /**
     * Resolve a list of roles to their corresponding email addresses.
     *
     * @param roles    List of role names (organization_admin, cert_manager, etc.)
     * @param organizationId Organization context – may be null
     * @param userId   User context (fallback) – may be null
     * @return List of unique email addresses
     */
    public List<String> resolveRolesToEmails(List<String> roles, Long organizationId, Long userId) {
        return resolveRolesToEmails(roles, organizationId, userId, false);
    }

    /**
     * As {@link #resolveRolesToEmails(List, Long, Long)}; with {@code includeUser}, the role holders of
     * the organization and also {@code userId} while that user is an active member of it, each
     * address once whatever its case. There is no fallback to a user who has left the organization.
     */
    public List<String> resolveRolesToEmails(List<String> roles, Long organizationId, Long userId, boolean includeUser) {
        if (includeUser && organizationId != null && userId != null) {
            return roleHoldersAndMember(roles, organizationId, userId);
        }
        if (roles == null || roles.isEmpty()) {
            return Collections.emptyList();
        }

        Set<String> emails = new LinkedHashSet<>();

        if (organizationId != null) {
            // Organization: look up users with each role in the organization
            for (String role : roles) {
                if (role == null || role.trim().isEmpty()) continue;
                String name = role.trim().toLowerCase();
                List<String> roleEmails = lookUp("role '" + name + "' in organization " + organizationId,
                        () -> userRepository.findEmailsByRoleAndOrganization(name, organizationId));
                if (roleEmails != null && !roleEmails.isEmpty()) {
                    emails.addAll(roleEmails);
                }
            }
            // If no users matched any role, fall back to the requesting user
            if (emails.isEmpty() && userId != null) {
                log.info("No users found for roles {} in organization {}, falling back to requesting user {}",
                        roles, organizationId, userId);
                resolveUserEmail(userId, emails);
            }
        } else if (userId != null) {
            // No organization: send to the user directly
            resolveUserEmail(userId, emails);
        } else {
            resolvePlatformRoleEmails(roles, emails);
        }

        if (emails.isEmpty()) {
            log.warn("No email addresses resolved for roles: {} in organization: {}, user: {}", roles, organizationId, userId);
        } else {
            log.debug("Resolved {} email(s) for roles: {} in organization: {}", emails.size(), roles, organizationId);
        }

        return new ArrayList<>(emails);
    }

    private List<String> roleHoldersAndMember(List<String> roles, Long organizationId, Long userId) {
        Map<String, String> byAddress = new LinkedHashMap<>();
        for (String role : roles == null ? List.<String>of() : roles) {
            if (role == null || role.isBlank()) {
                continue;
            }
            String name = role.trim().toLowerCase(Locale.ROOT);
            List<String> holders = lookUp("role '" + name + "' in organization " + organizationId,
                    () -> userRepository.findEmailsByRoleAndOrganization(name, organizationId));
            if (holders != null) {
                holders.forEach(email -> addOnce(byAddress, email));
            }
        }
        lookUp("member " + userId + " of organization " + organizationId,
                () -> userRepository.findEmailByUserIdInOrganization(userId, organizationId))
                .ifPresent(email -> addOnce(byAddress, email));
        return new ArrayList<>(byAddress.values());
    }

    private static void addOnce(Map<String, String> byAddress, String email) {
        if (email != null && !email.isBlank()) {
            byAddress.putIfAbsent(email.trim().toLowerCase(Locale.ROOT), email.trim());
        }
    }

    /**
     * Overload for backward compatibility.
     */
    public List<String> resolveRolesToEmails(List<String> roles, Long organizationId) {
        return resolveRolesToEmails(roles, organizationId, null);
    }

    private void resolvePlatformRoleEmails(List<String> roles, Set<String> emails) {
        boolean platformRoleRequested = false;
        for (String role : roles) {
            if (role == null) continue;
            String name = platformRoleName(role);
            if (!PLATFORM_ROLES.contains(name)) continue;
            platformRoleRequested = true;
            List<String> roleEmails = lookUp("platform role '" + name + "' holders",
                    () -> userRepository.findActivePlatformRoleEmails(name));
            if (roleEmails == null) continue;
            for (String email : roleEmails) {
                if (isDeliverable(email)) {
                    emails.add(email.trim());
                }
            }
        }
        if (platformRoleRequested && emails.isEmpty() && isDeliverable(bootstrapSuperAdminEmail)) {
            log.warn("No active holder of platform roles {}; sending to the bootstrap super-admin address", roles);
            emails.add(bootstrapSuperAdminEmail.trim());
        }
    }

    private static String platformRoleName(String role) {
        return role.trim().toUpperCase(Locale.ROOT);
    }

    private static boolean isDeliverable(String email) {
        return email != null && !email.isBlank() && !email.trim().equalsIgnoreCase(SEED_PLACEHOLDER_EMAIL);
    }

    private void resolveUserEmail(Long userId, Set<String> emails) {
        lookUp("user " + userId, () -> userRepository.findEmailByUserId(userId)).ifPresent(emails::add);
    }

    /**
     * A failed users query is a retryable failure: an empty answer would read as "nobody", and the
     * event would be recorded undeliverable although its recipients exist.
     */
    private static <T> T lookUp(String what, Supplier<T> query) {
        try {
            return query.get();
        } catch (RuntimeException e) {
            throw new RetryableNotificationException(RECIPIENT_LOOKUP_FAILED,
                    "Failed to look up " + what + ": " + e.getMessage(), LOOKUP_RETRY_AFTER, e);
        }
    }
}
