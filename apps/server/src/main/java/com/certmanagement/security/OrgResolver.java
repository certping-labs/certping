// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.exception.BadRequestException;
import org.jspecify.annotations.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.certmanagement.security.Permissions.ROLE_ORGANIZATION_ADMIN;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * Single source of truth for resolving the effective organization ID on any request.
 *
 * Three resolution modes:
 *  - resolve(Long)              strict   — super-admin MUST provide; non-super uses JWT, rejects override
 *  - resolveOptional(Long)      lenient  — super-admin may omit (null = global); non-super uses JWT (required), rejects override
 *  - resolveOptionalAllowNullJwt(Long)  — same as resolveOptional but non-super JWT may also be null (for catalog reads)
 *
 * Two raw JWT reads:
 *  - fromJwt()       — JWT org required, throws if absent
 *  - fromJwtOrNull() — JWT org optional, null if absent
 */
public final class OrgResolver {

    private OrgResolver() {}

    // ── Raw JWT reads ────────────────────────────────────────────────────────

    /** Returns the organization ID from the JWT. Throws {@link AccessDeniedException} if absent. */
    public static Long fromJwt() {
        String raw = GatewayRequestContext.getOrganizationId();
        if (raw == null || raw.isBlank()) {
            throw new AccessDeniedException("No organization context in token. Organization-scoped operations require an organization JWT.");
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException ex) {
            throw new AccessDeniedException("Invalid organization context in token.");
        }
    }

    /** Returns the organization ID from the JWT, or {@code null} if absent. */
    public static Long fromJwtOrNull() {
        String raw = GatewayRequestContext.getOrganizationId();
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException ex) {
            throw new AccessDeniedException("Invalid organization context in token.");
        }
    }

    // ── Scope resolution ─────────────────────────────────────────────────────

    /**
     * Strict resolution.
     * <ul>
     *   <li>Super-admin: {@code requestedOrgId} is used as-is; {@code null} falls back to the working
     *       organization in the JWT (the one chosen through {@code PUT /api/v1/admin/me/organization}), and
     *       throws {@link BadRequestException} when there is none either.</li>
     *   <li>Non-super-admin: JWT org is used; passing a different {@code requestedOrgId} throws {@link AccessDeniedException}.</li>
     * </ul>
     */
    public static Long resolve(Long requestedOrgId) {
        if (isSuperAdmin()) {
            if (requestedOrgId != null) {
                return requestedOrgId;
            }
            Long working = fromJwtOrNull();
            if (working == null) {
                throw new BadRequestException("organizationId is required for SUPER_ADMIN requests");
            }
            return working;
        }
        Long jwtOrg = fromJwt();
        if (requestedOrgId != null && !requestedOrgId.equals(jwtOrg)) {
            throw new AccessDeniedException("organizationId override is not allowed for organization-scoped users");
        }
        return jwtOrg;
    }

    /**
     * Convenience overload for String path variables (e.g. {@code @PathVariable String id}).
     * Parses the string first; {@link NumberFormatException} propagates as {@link IllegalArgumentException}.
     */
    public static Long resolve(String requestedOrgId) {
        return resolve(Long.parseLong(requestedOrgId));
    }

    /**
     * Optional resolution — for APIs where super-admin may operate globally.
     * <ul>
     *   <li>Super-admin: {@code requestedOrgId} returned as-is ({@code null} means global/all-orgs).</li>
     *   <li>Non-super-admin: JWT org is used (required); passing a different {@code requestedOrgId} throws {@link AccessDeniedException}.</li>
     * </ul>
     */
    public static Long resolveOptional(Long requestedOrgId) {
        if (isSuperAdmin()) {
            return requestedOrgId;
        }
        Long jwtOrg = fromJwt();
        if (requestedOrgId != null && !requestedOrgId.equals(jwtOrg)) {
            throw new AccessDeniedException("organizationId override is not allowed for organization-scoped users");
        }
        return jwtOrg;
    }

    /**
     * Optional resolution with a relaxed JWT requirement — for catalog/read endpoints
     * where a user without an organization JWT (e.g. a bootstrapped admin) should still
     * be able to read system-level data.
     * <ul>
     *   <li>Super-admin: {@code requestedOrgId} returned as-is ({@code null} means global).</li>
     *   <li>Non-super-admin: JWT org returned if present, {@code null} if absent; passing a different
     *       {@code requestedOrgId} throws {@link AccessDeniedException}.</li>
     * </ul>
     */
    public static Long resolveOptionalAllowNullJwt(Long requestedOrgId) {
        if (isSuperAdmin()) {
            return requestedOrgId;
        }
        Long jwtOrg = fromJwtOrNull();
        if (requestedOrgId != null) {
            if (jwtOrg == null || !requestedOrgId.equals(jwtOrg)) {
                throw new AccessDeniedException("organizationId override is not allowed for organization-scoped users");
            }
            return requestedOrgId;
        }
        return jwtOrg;
    }

    // ── Utility ──────────────────────────────────────────────────────────────

    /** An organization id given as a number or as its decimal text; {@code null} for anything else. */
    @Nullable
    public static Long toOrganizationId(@Nullable Object organizationId) {
        if (organizationId instanceof Number number) {
            return number.longValue();
        }
        if (organizationId instanceof CharSequence text) {
            try {
                return Long.parseLong(text.toString().trim());
            } catch (NumberFormatException notANumber) {
                return null;
            }
        }
        return null;
    }

    public static boolean isSuperAdmin() {
        return callerHasRole(ROLE_SUPER_ADMIN);
    }

    public static boolean isOrganizationAdmin() {
        return callerHasRole(ROLE_ORGANIZATION_ADMIN);
    }

    private static boolean callerHasRole(String role) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || auth.getAuthorities() == null) return false;
        return auth.getAuthorities().stream()
                .anyMatch(a -> ("ROLE_" + role).equals(a.getAuthority()));
    }
}
