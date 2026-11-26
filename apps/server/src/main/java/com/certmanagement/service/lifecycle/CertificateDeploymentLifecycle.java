// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.repository.lifecycle.AffectedOrganizations;
import com.certmanagement.repository.lifecycle.CertificateLifecycleRepository;
import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.repository.lifecycle.RecordImpact;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * {@code CERTIFICATE_DEPLOYMENT}: blocked while certificates still have deployment targets, which
 * auto-deploy would push to after every renewal; cleared by emptying every certificate's target list.
 * Certificates themselves are untouched.
 */
@Component
@RequiredArgsConstructor
public class CertificateDeploymentLifecycle implements FeatureLifecycle {

    private static final String LABEL = "Deployment targets";
    private static final String HREF = "/cert-manager/deployments";

    private final CertificateLifecycleRepository certificates;

    @Override
    public String featureKey() {
        return FeatureFlags.CERTIFICATE_DEPLOYMENT;
    }

    @Override
    public List<BlockerKind> kinds() {
        return List.of(BlockerKind.DEPLOYMENT_TARGETS);
    }

    @Override
    public Set<ClearAction> supportedActions(BlockerKind kind) {
        return kind == BlockerKind.DEPLOYMENT_TARGETS ? Set.of(ClearAction.CLEAR_TARGETS) : Set.of();
    }

    @Override
    public List<Blocker> blockers(long organizationId) {
        long targets = certificates.countDeploymentTargets(organizationId);
        return targets == 0 ? List.of() : List.of(new Blocker(BlockerKind.DEPLOYMENT_TARGETS, LABEL, targets, HREF,
                List.of(ClearAction.CLEAR_TARGETS)));
    }

    @Override
    public int clear(long organizationId, BlockerKind kind, ClearAction action) {
        if (!supportedActions(kind).contains(action)) {
            throw new UnsupportedClearException(featureKey(), kind, action);
        }
        return Math.toIntExact(certificates.clearDeploymentTargets(organizationId));
    }

    @Override
    public List<ImpactCount> impact(ImpactScope scope) {
        RecordImpact impact = certificates.deploymentTargetsImpact(scope);
        return List.of(new ImpactCount(BlockerKind.DEPLOYMENT_TARGETS, LABEL, impact.records(),
                impact.organizations()));
    }

    @Override
    public List<AffectedOrganizations> affectedOrganizations(ImpactScope scope) {
        return List.of(certificates.deploymentTargetOrganizations(scope));
    }
}
