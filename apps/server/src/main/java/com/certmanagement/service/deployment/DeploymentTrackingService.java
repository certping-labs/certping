// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.entity.DeploymentEntity;
import com.certmanagement.enums.DeploymentStatus;
import com.certmanagement.enums.EventSource;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DeploymentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@lombok.extern.slf4j.Slf4j
@Service
@RequiredArgsConstructor
public class DeploymentTrackingService {

    /** How adapters report the target's HTTP status in a failure detail, e.g. "(HTTP 401, debugId=...)". */
    private static final Pattern REFUSED_STATUS =
            Pattern.compile("\\b(?:HTTP|status(?: code)?)[ :=]*(401|403)\\b", Pattern.CASE_INSENSITIVE);

    private final DeploymentRepository deploymentRepository;
    private final CredentialReferenceRepository credentialReferenceRepository;

    @Transactional
    public void createRequested(String requestId,
                                String correlationId,
                                Long organizationId,
                                String certificateXref,
                                Long userDomainCertId,
                                String deploymentCredentialXref,
                                String targetType,
                                String flowType,
                                String certSecretHandle,
                                String deploymentCredHandle,
                                Map<String, Object> metadata) {
        DeploymentEntity d = DeploymentEntity.builder()
                .requestId(requestId)
                .correlationId(correlationId)
                .organizationId(organizationId)
                .certificateXref(certificateXref)
                .userDomainCertId(userDomainCertId)
                .deploymentCredentialXref(deploymentCredentialXref)
                .targetType(targetType)
                .flowType(flowType)
                .status(DeploymentStatus.DEPLOYING.name())
                .certSecretHandle(certSecretHandle)
                .deploymentCredHandle(deploymentCredHandle)
                .requestedAt(OffsetDateTime.now(ZoneOffset.UTC))
                .source(EventSource.CERT_MANAGER.value())
                .metadata(metadata)
                .build();
        deploymentRepository.save(d);
    }

    @Transactional
    public void markPublished(String requestId) {
        deploymentRepository.findByRequestId(requestId).ifPresent(d -> {
            d.setStatus(DeploymentStatus.DEPLOYING.name());
            d.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));
            d.setSource(EventSource.CERT_MANAGER.value());
            deploymentRepository.save(d);
        });
    }

    /**
     * Mark deployment as published with organization scoping for defense-in-depth.
     * Verifies that the deployment belongs to the calling organization before updating.
     *
     * @param requestId The deployment request ID
     * @param organizationId The organization ID (must match deployment's organization)
     */
    @Transactional
    public void markPublished(String requestId, Long organizationId) {
        deploymentRepository.findByRequestIdAndOrganizationId(requestId, organizationId).ifPresent(d -> {
            d.setStatus(DeploymentStatus.DEPLOYING.name());
            d.setPublishedAt(OffsetDateTime.now(ZoneOffset.UTC));
            d.setSource(EventSource.CERT_MANAGER.value());
            deploymentRepository.save(d);
        });
    }

    @Transactional
    public void markPublishFailed(String requestId, String errorCode, String errorDetail) {
        deploymentRepository.findByRequestId(requestId).ifPresent(d -> {
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            d.setStatus(DeploymentStatus.PUBLISH_FAILED.name());
            d.setErrorCode(errorCode);
            d.setErrorDetail(errorDetail);
            d.setCompletedAt(now);
            d.setSource(EventSource.CERT_MANAGER.value());
            deploymentRepository.save(d);
        });
    }

    /**
     * Mark deployment publish as failed with organization scoping for defense-in-depth.
     * Verifies that the deployment belongs to the calling organization before updating.
     *
     * @param requestId The deployment request ID
     * @param organizationId The organization ID (must match deployment's organization)
     * @param errorCode The error code
     * @param errorDetail The error detail
     */
    @Transactional
    public void markPublishFailed(String requestId, Long organizationId, String errorCode, String errorDetail) {
        deploymentRepository.findByRequestIdAndOrganizationId(requestId, organizationId).ifPresent(d -> {
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            d.setStatus(DeploymentStatus.PUBLISH_FAILED.name());
            d.setErrorCode(errorCode);
            d.setErrorDetail(errorDetail);
            d.setCompletedAt(now);
            d.setSource(EventSource.CERT_MANAGER.value());
            deploymentRepository.save(d);
        });
    }

    @Transactional
    public void markSuccess(String requestId, String targetResourceId, OffsetDateTime respondedAt) {
        deploymentRepository.findByRequestId(requestId).ifPresent(d -> {
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            d.setStatus(DeploymentStatus.SUCCESS.name());
            d.setTargetResourceId(targetResourceId);
            d.setRespondedAt(respondedAt != null ? respondedAt : now);
            d.setCompletedAt(now);
            d.setSource(EventSource.AGENT.value());
            deploymentRepository.save(d);
        });
    }

    /**
     * Mark deployment as successful with organization scoping for defense-in-depth.
     * Verifies that the deployment belongs to the calling organization before updating.
     *
     * @param requestId The deployment request ID
     * @param organizationId The organization ID (must match deployment's organization)
     * @param targetResourceId The target resource ID
     * @param respondedAt The response timestamp
     */
    @Transactional
    public void markSuccess(String requestId, Long organizationId, String targetResourceId, OffsetDateTime respondedAt) {
        deploymentRepository.findByRequestIdAndOrganizationId(requestId, organizationId).ifPresent(d -> {
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            d.setStatus(DeploymentStatus.SUCCESS.name());
            d.setTargetResourceId(targetResourceId);
            d.setRespondedAt(respondedAt != null ? respondedAt : now);
            d.setCompletedAt(now);
            d.setSource(EventSource.AGENT.value());
            deploymentRepository.save(d);
            if (d.getDeploymentCredentialXref() != null) {
                credentialReferenceRepository.clearLastError(d.getDeploymentCredentialXref(), organizationId);
            }
        });
    }

    @Transactional
    public void markFailed(String requestId, String errorCode, String errorDetail, OffsetDateTime respondedAt) {
        deploymentRepository.findByRequestId(requestId).ifPresent(d -> {
            if (DeploymentStatus.SUCCESS.name().equals(d.getStatus())) {
                // A late duplicate delivery failed after another one already deployed: keep the success.
                log.info("Ignoring stale deployment failure for requestId={}: already SUCCESS (errorCode={})",
                        requestId, errorCode);
                return;
            }
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            d.setStatus(DeploymentStatus.FAILED.name());
            d.setErrorCode(errorCode);
            d.setErrorDetail(errorDetail);
            d.setRespondedAt(respondedAt != null ? respondedAt : now);
            d.setCompletedAt(now);
            d.setSource(EventSource.AGENT.value());
            deploymentRepository.save(d);
        });
    }

    /**
     * Mark deployment as failed with organization scoping for defense-in-depth.
     * Verifies that the deployment belongs to the calling organization before updating.
     *
     * @param requestId The deployment request ID
     * @param organizationId The organization ID (must match deployment's organization)
     * @param errorCode The error code
     * @param errorDetail The error detail
     * @param respondedAt The response timestamp
     */
    @Transactional(readOnly = true)
    public Optional<DeploymentEntity> findByRequestId(String requestId) {
        return deploymentRepository.findByRequestId(requestId);
    }

    /**
     * Looks up a deployment scoped to the authenticated organization. A validly signed message can
     * name another organization's requestId; unscoped reads leak that organization's deployment
     * details into the caller's notification payload, so this is the variant the message path uses.
     */
    @Transactional(readOnly = true)
    public Optional<DeploymentEntity> findByRequestIdAndOrganizationId(String requestId, Long organizationId) {
        return deploymentRepository.findByRequestIdAndOrganizationId(requestId, organizationId);
    }

    @Transactional
    public void markFailed(String requestId, Long organizationId, String errorCode, String errorDetail, OffsetDateTime respondedAt) {
        deploymentRepository.findByRequestIdAndOrganizationId(requestId, organizationId).ifPresent(d -> {
            if (DeploymentStatus.SUCCESS.name().equals(d.getStatus())) {
                // A late duplicate delivery failed after another one already deployed: keep the success.
                log.info("Ignoring stale deployment failure for requestId={}: already SUCCESS (errorCode={})",
                        requestId, errorCode);
                return;
            }
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            d.setStatus(DeploymentStatus.FAILED.name());
            d.setErrorCode(errorCode);
            d.setErrorDetail(errorDetail);
            d.setRespondedAt(respondedAt != null ? respondedAt : now);
            d.setCompletedAt(now);
            d.setSource(EventSource.AGENT.value());
            deploymentRepository.save(d);
            String refusal = credentialRefusal(errorCode, errorDetail);
            if (refusal != null && d.getDeploymentCredentialXref() != null) {
                credentialReferenceRepository.recordLastError(d.getDeploymentCredentialXref(), organizationId,
                        refusal + " on " + now.withNano(0) + ". Rotate the secret or check its permissions.");
            }
        });
    }

    /**
     * What to show on the credential when the target refused it (an expired token, a revoked key, missing rights),
     * or null for any other failure. A later successful deployment or an update of the credential clears it.
     */
    static String credentialRefusal(String errorCode, String errorDetail) {
        if (errorDetail != null) {
            Matcher status = REFUSED_STATUS.matcher(errorDetail);
            if (status.find()) {
                return "The deployment target refused this credential (HTTP " + status.group(1) + ")";
            }
        }
        if (errorCode != null && (errorCode.contains("_AUTH_") || errorCode.endsWith("CREDENTIAL_INVALID"))) {
            return "The deployment target refused this credential (" + errorCode + ")";
        }
        return null;
    }
}
