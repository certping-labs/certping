// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.security.Permissions;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static com.certmanagement.service.lifecycle.ClearAction.CANCEL_ALL;
import static com.certmanagement.service.lifecycle.ClearAction.CLEAR_TARGETS;
import static com.certmanagement.service.lifecycle.ClearAction.DELETE_ALL;
import static com.certmanagement.service.lifecycle.ClearAction.DISABLE_AUTO_RENEW;
import static com.certmanagement.service.lifecycle.ClearAction.PAUSE_ALL;

/**
 * The permission each bulk clear needs on top of {@code feature_flags:manage}: the one the same change
 * needs one record at a time, so a bulk clear never lets anyone do more than the record pages allow.
 * The one place both {@code POST …/clear} (403 without it) and {@code GET …/disable-check} (only offers
 * the actions the caller may perform) read.
 *
 * <p>Deny by default: a (kind, action) pair missing here is never permitted, and
 * {@code ClearPermissionsTest} fails when a lifecycle offers an action this map does not cover.
 */
public final class ClearPermissions {

    private static final Map<BlockerKind, Map<ClearAction, String>> REQUIRED = new EnumMap<>(Map.of(
            // DomainCredentialConfigController adds, edits and DELETEs a deployment target with
            // certificate:issue; certificate:deploy only pushes a certificate to targets already set.
            BlockerKind.DEPLOYMENT_TARGETS, Map.of(CLEAR_TARGETS, Permissions.CERTIFICATE_ISSUE),
            BlockerKind.AUTO_RENEW_CERTS, Map.of(DISABLE_AUTO_RENEW, Permissions.CERTIFICATE_RENEW),
            BlockerKind.AUTO_RENEW_CERTS_ON_CA, Map.of(DISABLE_AUTO_RENEW, Permissions.CERTIFICATE_RENEW),
            // Discovery scans run with a deployment credential; triggering one needs certificate:deploy.
            BlockerKind.RUNNING_DISCOVERY_SCANS, Map.of(CANCEL_ALL, Permissions.CERTIFICATE_DEPLOY)));

    private ClearPermissions() {
    }

    /** The permission {@code action} on {@code kind} needs, or empty when it is never permitted. */
    public static Optional<String> requiredPermission(BlockerKind kind, ClearAction action) {
        return Optional.ofNullable(REQUIRED.getOrDefault(kind, Map.of()).get(action));
    }

    /** Whether a caller holding {@code callerPermissions} may apply {@code action} to {@code kind}. */
    public static boolean permits(BlockerKind kind, ClearAction action, Set<String> callerPermissions) {
        return requiredPermission(kind, action).map(callerPermissions::contains).orElse(false);
    }

    /** {@code blockers} with each one's actions narrowed to those the caller may perform. */
    public static List<Blocker> withPermittedActions(List<Blocker> blockers, Set<String> callerPermissions) {
        return blockers.stream()
                .map(blocker -> new Blocker(blocker.kind(), blocker.label(), blocker.count(), blocker.href(),
                        blocker.actions().stream()
                                .filter(action -> permits(blocker.kind(), action, callerPermissions))
                                .toList()))
                .toList();
    }
}
