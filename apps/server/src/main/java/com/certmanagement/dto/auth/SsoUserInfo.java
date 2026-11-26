// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.auth;

import lombok.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * DTO representing user information extracted from an SSO IdP response (an OIDC token).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SsoUserInfo {

    private String email;
    private String idpUserId;
    private String firstName;
    private String lastName;
    private String displayName;
    
    // Groups from IDP (Azure AD groups, Okta groups, etc.)
    @Builder.Default
    private Set<String> groups = new HashSet<>();
    
    // Roles from IDP (custom role claims, Azure app roles, etc.)
    @Builder.Default
    private Set<String> roles = new HashSet<>();
    
    // All attributes from the IDP token
    @Builder.Default
    private Map<String, Object> attributes = new HashMap<>();
    
    private String authMethod; // OIDC
    private String provider;   // IdP registration ID
    private String organizationDomain;

    public String getFullName() {
        if (displayName != null && !displayName.isBlank()) {
            return displayName;
        }
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        }
        return email;
    }
}
