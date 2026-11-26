// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.constants;

public enum ActionType {
    API_READ,
    API_CREATE,
    API_UPDATE,
    API_PATCH,
    API_DELETE,
    SSO_LOGIN,
    SSO_LOGIN_FAILURE,
    SSO_LOGOUT,
    CREATE,
    UPDATE,
    DELETE,
    CONFIGURE,
    TOGGLE,
    ROTATE,
    // Who may do what: written in the same transaction as the change, with the before and after.
    ROLE_CREATED,
    ROLE_DELETED,
    ROLE_PERMISSIONS_CHANGED,
    USER_ROLES_CHANGED,
    USER_PERMISSIONS_CHANGED,
    USER_CREATED,
    USER_ENABLED,
    USER_DISABLED,
    USER_DELETED,
    USER_EMAIL_CHANGED,
    SSO_ROLE_MAPPING_CHANGED,
    SSO_ROLES_ASSIGNED,
    // Feature flags: every global, org-type and org write, with before/after and the operator's reason.
    FEATURE_FLAG_CHANGED,
    FEATURE_FLAG_OVERRIDE_REMOVED,
    // Feature lifecycle: an org admin's bulk clear, and the platform pausing / resuming a feature's records.
    FEATURE_CLEARED,
    FEATURE_PLATFORM_PAUSED,
    FEATURE_PLATFORM_RESUMED,
    // Incidents and integrations.
    INCIDENT_TRIGGER,
    INTEGRATION_CREATE,
    INTEGRATION_UPDATE,
    INTEGRATION_DELETE,
    INTEGRATION_NOTIFY,
    // A certificate's material left the platform as a file; details name the format, never the material.
    CERTIFICATE_EXPORTED
}
