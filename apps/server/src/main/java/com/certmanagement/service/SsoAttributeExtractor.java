// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.security.oidc.SsoConfig;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;
import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

/**
 * Service for extracting user attributes from OIDC and OAuth2 responses.
 * Supports custom claim names for roles and groups.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SsoAttributeExtractor {

    private final ObjectMapper objectMapper;

    // Common attribute names for the email address and the name, read from a plain OAuth2 user
    private static final String[] EMAIL_ATTRS = {
        "email", "emailAddress", "mail",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "http://schemas.xmlsoap.org/claims/EmailAddress",
        "urn:oid:0.9.2342.19200300.100.1.3"
    };

    private static final String[] FIRST_NAME_ATTRS = {
        "firstName", "givenName", "given_name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "urn:oid:2.5.4.42"
    };

    private static final String[] LAST_NAME_ATTRS = {
        "lastName", "surname", "sn", "family_name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        "urn:oid:2.5.4.4"
    };

    // Common role/group claim names
    private static final String[] DEFAULT_ROLE_CLAIMS = {
        "roles", "role", "Role", "Roles",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/roles"
    };

    /** Key in {@code SsoConfig.attributeMapping} naming the claim to use as the subject. */
    private static final String USER_ID_MAPPING_KEY = "userId";

    private static final String ENTRA_OID_CLAIM = "oid";
    private static final String ENTRA_TID_CLAIM = "tid";

    private static final String[] DEFAULT_GROUP_CLAIMS = {
        "groups", "group", "Group", "Groups", "memberOf",
        "http://schemas.xmlsoap.org/claims/Group",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    };

    /**
     * The claim an organization has nominated as its subject identifier, via the {@code userId} key
     * of its attribute mapping, for an IdP that exposes a stable ID only under a name the customer
     * chooses.
     */
    private String configuredSubjectAttribute(SsoConfig ssoConfig) {
        if (ssoConfig == null || ssoConfig.getAttributeMapping() == null
                || ssoConfig.getAttributeMapping().isBlank()) {
            return null;
        }
        try {
            Map<String, String> mapping = objectMapper.readValue(
                    ssoConfig.getAttributeMapping(), new TypeReference<Map<String, String>>() {});
            String configured = mapping.get(USER_ID_MAPPING_KEY);
            return configured == null || configured.isBlank() ? null : configured.trim();
        } catch (Exception e) {
            contextLogger().warn("Failed to read subject attribute from attribute mapping: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Trim and discard blanks. Never case-folded: that would collide distinct base64-style
     * identifiers.
     */
    private String normalizeSubject(String rawValue) {
        if (rawValue == null) {
            return null;
        }
        String trimmed = rawValue.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * Extract user info from OIDC user.
     */
    public SsoUserInfo extractFromOidc(OidcUser oidcUser, String registrationId) {
        return extractFromOidc(oidcUser, registrationId, null);
    }

    private SsoUserInfo extractFromOidcInternal(OidcUser oidcUser, String registrationId, SsoConfig ssoConfig) {
        contextLogger().debug("Extracting user info from OIDC user: {}", oidcUser.getSubject());

        String email = oidcUser.getEmail();
        if (email == null) {
            email = extractOidcAttribute(oidcUser, "email", "mail", "preferred_username");
        }

        return SsoUserInfo.builder()
            .email(email)
            .idpUserId(resolveOidcSubject(oidcUser, ssoConfig))
            .firstName(oidcUser.getGivenName())
            .lastName(oidcUser.getFamilyName())
            .displayName(oidcUser.getFullName())
            .groups(extractOidcGroups(oidcUser, ssoConfig != null ? ssoConfig.getGroupsClaimName() : null))
            .roles(extractOidcRoles(oidcUser, ssoConfig != null ? ssoConfig.getRolesClaimName() : null))
            .attributes(new HashMap<>(oidcUser.getClaims()))
            .authMethod("OIDC")
            .provider(registrationId)
            .organizationDomain(extractDomainFromEmail(email))
            .build();
    }

    /**
     * Extract user info from OIDC user with custom claim configuration.
     */
    public SsoUserInfo extractFromOidc(OidcUser oidcUser, String registrationId, SsoConfig ssoConfig) {
        return extractFromOidcInternal(oidcUser, registrationId, ssoConfig);
    }

    /**
     * Resolve the OIDC subject.
     *
     * <p>{@code sub} is the right answer nearly everywhere — the spec forbids reassigning it within
     * an issuer. Entra is the exception worth handling: its {@code sub} is pairwise per application
     * client ID, while {@code oid} is the tenant-wide object ID shared across applications. Storing
     * {@code oid} keeps a user's identity intact across client-ID rotation or a new app
     * registration, which pairwise {@code sub} would not survive.
     */
    private String resolveOidcSubject(OidcUser oidcUser, SsoConfig ssoConfig) {
        String configuredClaim = configuredSubjectAttribute(ssoConfig);
        if (configuredClaim != null) {
            Object value = oidcUser.getClaims().get(configuredClaim);
            String resolved = normalizeSubject(value != null ? value.toString() : null);
            if (resolved != null) {
                return resolved;
            }
            contextLogger().warn("Configured subject claim '{}' absent from token — falling back", configuredClaim);
        }

        // Gate on tid as well as oid: a claim merely named "oid" from some other IdP carries no
        // promise about its semantics.
        Object oid = oidcUser.getClaims().get(ENTRA_OID_CLAIM);
        Object tid = oidcUser.getClaims().get(ENTRA_TID_CLAIM);
        if (oid != null && tid != null) {
            String resolved = normalizeSubject(oid.toString());
            if (resolved != null) {
                contextLogger().debug("Resolved OIDC subject from Entra oid claim");
                return resolved;
            }
        }

        return normalizeSubject(oidcUser.getSubject());
    }

    /**
     * Extract user info from generic OAuth2 user (non-OIDC).
     */
    public SsoUserInfo extractFromOAuth2(OAuth2User oauth2User, String registrationId) {
        contextLogger().debug("Extracting user info from OAuth2 user");

        String email = extractOidcAttribute(oauth2User, EMAIL_ATTRS);
        if (email == null) {
            email = oauth2User.getName();
        }

        return SsoUserInfo.builder()
            .email(email)
            .idpUserId(normalizeSubject(oauth2User.getName()))
            .firstName(extractOidcAttribute(oauth2User, FIRST_NAME_ATTRS))
            .lastName(extractOidcAttribute(oauth2User, LAST_NAME_ATTRS))
            .displayName(extractOidcAttribute(oauth2User, "name", "displayName"))
            .groups(extractOidcGroups(oauth2User, null))
            .roles(extractOidcRoles(oauth2User, null))
            .attributes(new HashMap<>(oauth2User.getAttributes()))
            .authMethod("OIDC")
            .provider(registrationId)
            .organizationDomain(extractDomainFromEmail(email))
            .build();
    }

    /**
     * Extract user info from generic OAuth2 user with custom claim configuration.
     */
    public SsoUserInfo extractFromOAuth2(OAuth2User oauth2User, String registrationId, SsoConfig ssoConfig) {
        SsoUserInfo userInfo = extractFromOAuth2(oauth2User, registrationId);
        
        if (ssoConfig != null) {
            userInfo.setGroups(extractOidcGroups(oauth2User, ssoConfig.getGroupsClaimName()));
            userInfo.setRoles(extractOidcRoles(oauth2User, ssoConfig.getRolesClaimName()));
        }
        
        return userInfo;
    }

    /**
     * Apply custom attribute mapping from SSO config.
     */
    public SsoUserInfo applyAttributeMapping(SsoUserInfo userInfo, String attributeMappingJson) {
        if (attributeMappingJson == null || attributeMappingJson.isBlank()) {
            return userInfo;
        }

        try {
            Map<String, String> mapping = objectMapper.readValue(
                attributeMappingJson, 
                new TypeReference<Map<String, String>>() {}
            );

            Map<String, Object> attrs = userInfo.getAttributes();

            // Apply custom mappings
            if (mapping.containsKey("email") && attrs.containsKey(mapping.get("email"))) {
                userInfo.setEmail(attrs.get(mapping.get("email")).toString());
            }
            if (mapping.containsKey("firstName") && attrs.containsKey(mapping.get("firstName"))) {
                userInfo.setFirstName(attrs.get(mapping.get("firstName")).toString());
            }
            if (mapping.containsKey("lastName") && attrs.containsKey(mapping.get("lastName"))) {
                userInfo.setLastName(attrs.get(mapping.get("lastName")).toString());
            }
            if (mapping.containsKey("displayName") && attrs.containsKey(mapping.get("displayName"))) {
                userInfo.setDisplayName(attrs.get(mapping.get("displayName")).toString());
            }

        } catch (Exception e) {
            contextLogger().warn("Failed to apply attribute mapping: {}", e.getMessage());
        }

        return userInfo;
    }

    // ============== OIDC/OAuth2 Attribute Extraction ==============

    private String extractOidcAttribute(OAuth2User user, String... attributeNames) {
        Map<String, Object> attrs = user.getAttributes();
        for (String attr : attributeNames) {
            Object value = attrs.get(attr);
            if (value != null) {
                return value.toString();
            }
        }
        return null;
    }

    private Set<String> extractOidcGroups(OAuth2User user, String customClaimName) {
        Set<String> groups = new HashSet<>();
        Map<String, Object> attrs = user.getAttributes();
        
        // Try custom claim name first
        if (customClaimName != null && !customClaimName.isBlank()) {
            Object value = attrs.get(customClaimName);
            if (value != null) {
                extractCollectionValues(value, groups);
                contextLogger().debug("Extracted {} groups from custom claim: {}", groups.size(), customClaimName);
                return groups;
            }
        }
        
        // Try default group claim names
        for (String claimName : DEFAULT_GROUP_CLAIMS) {
            Object value = attrs.get(claimName);
            if (value != null) {
                extractCollectionValues(value, groups);
            }
        }
        
        contextLogger().debug("Extracted {} groups from OIDC token", groups.size());
        return groups;
    }

    private Set<String> extractOidcRoles(OAuth2User user, String customClaimName) {
        Set<String> roles = new HashSet<>();
        Map<String, Object> attrs = user.getAttributes();
        
        // Try custom claim name first
        if (customClaimName != null && !customClaimName.isBlank()) {
            Object value = attrs.get(customClaimName);
            if (value != null) {
                extractCollectionValues(value, roles);
                contextLogger().debug("Extracted {} roles from custom claim: {}", roles.size(), customClaimName);
                return roles;
            }
        }
        
        // Try default role claim names
        for (String claimName : DEFAULT_ROLE_CLAIMS) {
            Object value = attrs.get(claimName);
            if (value != null) {
                extractCollectionValues(value, roles);
            }
        }
        
        contextLogger().debug("Extracted {} roles from OIDC token", roles.size());
        return roles;
    }

    /**
     * Extract values from a claim that could be a single value, array, or collection.
     */
    private void extractCollectionValues(Object value, Set<String> target) {
        if (value instanceof Collection<?> collection) {
            collection.forEach(v -> target.add(v.toString()));
        } else if (value instanceof String[] strings) {
            Collections.addAll(target, strings);
        } else if (value != null) {
            target.add(value.toString());
        }
    }

    private String extractDomainFromEmail(String email) {
        if (email != null && email.contains("@")) {
            return email.substring(email.indexOf("@") + 1);
        }
        return null;
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(SsoAttributeExtractor.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
