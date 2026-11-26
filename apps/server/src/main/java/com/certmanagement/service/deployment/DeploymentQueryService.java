// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.dto.deployment.DeploymentQueryRequest;
import com.certmanagement.dto.deployment.DeploymentSummaryDto;
import com.certmanagement.dto.deployment.UserDomainCertDeploymentSummaryDto;
import com.certmanagement.entity.CertDeploymentConfigEntity;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DeploymentEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.CertDeploymentConfigRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.service.cert.CredentialReferenceService;
import com.certmanagement.util.UserFacingErrorMessages;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DeploymentQueryService {

    private final DeploymentRepository deploymentRepository;
    private final CertificateRepository certificateRepository;
    private final CertDeploymentConfigRepository certDeploymentConfigRepository;
    private final CredentialReferenceService credentialReferenceService;

    @Transactional(readOnly = true)
    public Object query(Long organizationId, DeploymentQueryRequest filter, Pageable pageable) {
        String view = filter.getView() == null ? "list" : filter.getView().toLowerCase();
        String requestId = blankToNull(filter.getRequestId());
        String certificateXref = blankToNull(filter.getCertificateXref());
        String status = blankToNull(filter.getStatus());
        String targetType = blankToNull(filter.getTargetType());
        String flowType = blankToNull(filter.getFlowType());
        Long userDomainCertId = filter.getUserDomainCertId();
        boolean filterByUserDomainCert = userDomainCertId != null;

        if (requestId != null) {
            DeploymentEntity one = deploymentRepository
                    .findActiveByRequestIdAndOrganizationId(requestId, organizationId)
                    .orElseThrow(() -> new IllegalArgumentException("Deployment not found for requestId=" + requestId));
            CertificateEntity cert = certificateRepository
                .findByCertificateXrefAndOrganizationId(one.getCertificateXref(), organizationId)
                .orElse(null);
            return Map.of("mode", "single", "item", toDeploymentResponse(one, cert));
        }

        if ("summary".equals(view)) {
            Object[] rawSummary = deploymentRepository.summary(
                    organizationId,
                    certificateXref,
                    status,
                    targetType,
                    flowType,
                    filterByUserDomainCert,
                    userDomainCertId,
                    filter.getFrom(),
                    filter.getTo());

            Object[] s = normalizeSummary(rawSummary);

            DeploymentSummaryDto summary = DeploymentSummaryDto.builder()
                    .total(toLong(s[0]))
                    .success(toLong(s[1]))
                    .failed(toLong(s[2]))
                    .publishFailed(toLong(s[3]))
                    .inProgress(toLong(s[4]))
                    .build();
            return Map.of("mode", "summary", "summary", summary);
        }

        Page<DeploymentEntity> page = deploymentRepository.search(
                organizationId,
            certificateXref,
            status,
            targetType,
            flowType,
                filterByUserDomainCert,
                userDomainCertId,
                filter.getFrom(),
                filter.getTo(),
                pageable);

        Map<String, CertificateEntity> certByXref = loadCertificatesByXref(organizationId, page.getContent());
        List<Map<String, Object>> items = page.getContent().stream()
            .map(deployment -> toDeploymentResponse(deployment, certByXref.get(deployment.getCertificateXref())))
            .toList();

        return Map.of(
                "mode", "list",
            "items", items,
                "page", page.getNumber(),
                "size", page.getSize(),
                "totalItems", page.getTotalElements(),
                "totalPages", page.getTotalPages());
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getCredentialConfig(Long organizationId, String certXref, String depCredXref) {
        String normalizedCertXref = blankToNull(certXref);
        String normalizedDepCredXref = blankToNull(depCredXref);
        if (normalizedCertXref == null || normalizedDepCredXref == null) {
            throw new BadRequestException("Both certXref and deploymentCredentialXref are required");
        }

        CertificateEntity cert = certificateRepository
                .findByCertificateXrefAndOrganizationId(normalizedCertXref, organizationId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Certificate '" + normalizedCertXref + "' not found for organization"));
        if (cert.getUserDomainCertId() == null) {
            throw new BadRequestException("Certificate has no userDomainCertId");
        }
        CredentialReferenceEntity credential = credentialReferenceService.getByXref(organizationId, normalizedDepCredXref);
        if (!"DEPLOYMENT".equals(credential.getType())) {
            throw new BadRequestException(
                    "credentialXref '" + normalizedDepCredXref + "' must be type DEPLOYMENT, found: " + credential.getType());
        }
        if (!"ACTIVE".equals(credential.getStatus())) {
            throw new BadRequestException("credentialXref '" + normalizedDepCredXref + "' is not ACTIVE");
        }

        CertDeploymentConfigEntity entity = certDeploymentConfigRepository
                .findActiveByCertAndCredentialXref(
                        organizationId, cert.getUserDomainCertId(), normalizedDepCredXref)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Deployment config not found for certXref '" + normalizedCertXref
                                + "' and deploymentCredentialXref '" + normalizedDepCredXref + "'"));
        if (!credential.getId().equals(entity.getDeploymentCredentialId())) {
            throw new ResourceNotFoundException(
                    "Deployment config mismatch for certXref '" + normalizedCertXref
                            + "' and deploymentCredentialXref '" + normalizedDepCredXref + "'");
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("certXref", normalizedCertXref);
        out.put("domain", cert.getDomain());
        out.put("organizationId", organizationId);
        out.put("userDomainCertId", cert.getUserDomainCertId());
        out.put("deploymentCredentialXref", entity.getDeploymentCredentialXref());
        out.put("deploymentCredentialId", entity.getDeploymentCredentialId());
        out.put("provider", entity.getProvider());
        out.put("config", entity.getConfigJson());
        out.put("createdAt", entity.getCreatedAt());
        out.put("updatedAt", entity.getUpdatedAt());
        return out;
    }

        @Transactional(readOnly = true)
        public Map<String, Object> listUserDomainCertDeploymentSummary(
            Long organizationId,
            String domain,
            Long userDomainCertId,
            boolean excludeEmpty,
            Pageable pageable) {
        String domainFilter = blankToNull(domain);
        boolean filterByUserDomainCert = userDomainCertId != null;
        Page<Object[]> page = deploymentRepository.summarizeByUserDomainCert(
                organizationId,
                domainFilter,
            filterByUserDomainCert,
                userDomainCertId,
                excludeEmpty,
                pageable);

        List<UserDomainCertDeploymentSummaryDto> items = page.getContent().stream()
            .map(row -> UserDomainCertDeploymentSummaryDto.builder()
                .userDomainCertId((Long) row[0])
                .domain((String) row[1])
                .deploymentsRequested(toLong(row[2]))
                .deploymentsSucceeded(toLong(row[3]))
                .deploymentsFailed(toLong(row[4]))
                .build())
            .toList();

        return Map.of(
            "items", items,
            "page", page.getNumber(),
            "size", page.getSize(),
            "totalItems", page.getTotalElements(),
            "totalPages", page.getTotalPages());
        }

    private String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    private Object[] normalizeSummary(Object[] rawSummary) {
        if (rawSummary == null || rawSummary.length == 0) {
            return new Object[]{0L, 0L, 0L, 0L, 0L};
        }
        if (rawSummary.length == 1 && rawSummary[0] instanceof Object[] nested) {
            return nested;
        }
        return rawSummary;
    }

    private long toLong(Object o) {
        if (o == null) {
            return 0L;
        }
        return ((Number) o).longValue();
    }

    private Map<String, CertificateEntity> loadCertificatesByXref(Long organizationId, List<DeploymentEntity> deployments) {
        Set<String> xrefs = deployments.stream()
                .map(DeploymentEntity::getCertificateXref)
                .filter(xref -> xref != null && !xref.isBlank())
                .collect(Collectors.toSet());

        if (xrefs.isEmpty()) {
            return Collections.emptyMap();
        }

        return certificateRepository.findByOrganizationIdAndCertificateXrefIn(organizationId, new ArrayList<>(xrefs)).stream()
                .collect(Collectors.toMap(CertificateEntity::getCertificateXref, Function.identity()));
    }

    private Map<String, Object> toDeploymentResponse(DeploymentEntity deployment, CertificateEntity cert) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", deployment.getId());
        out.put("requestId", deployment.getRequestId());
        out.put("correlationId", deployment.getCorrelationId());
        out.put("organizationId", deployment.getOrganizationId());
        out.put("certificateXref", deployment.getCertificateXref());
        out.put("deploymentCredentialXref", deployment.getDeploymentCredentialXref());
        out.put("targetType", deployment.getTargetType());
        out.put("flowType", deployment.getFlowType());
        out.put("status", deployment.getStatus());
        out.put("certSecretHandle", deployment.getCertSecretHandle());
        out.put("deploymentCredHandle", deployment.getDeploymentCredHandle());
        out.put("targetResourceId", deployment.getTargetResourceId());
        // Raw errorCode/errorDetail are intentionally NOT exposed — they may carry internal
        // system detail. Surface only a sanitized, user-facing message derived from the code.
        if (deployment.getErrorCode() != null || deployment.getErrorDetail() != null) {
            out.put("userMessage", UserFacingErrorMessages.forCode(deployment.getErrorCode()));
        }
        out.put("requestedAt", deployment.getRequestedAt());
        out.put("publishedAt", deployment.getPublishedAt());
        out.put("respondedAt", deployment.getRespondedAt());
        out.put("completedAt", deployment.getCompletedAt());
        out.put("source", deployment.getSource());
        out.put("metadata", deployment.getMetadata());
        out.put("createdAt", deployment.getCreatedAt());
        out.put("updatedAt", deployment.getUpdatedAt());

        out.put("domain", cert != null ? cert.getDomain() : null);
        out.put("userDomainCertId", cert != null ? cert.getUserDomainCertId() : null);
        out.put("wildcard", cert != null ? cert.getWildcard() : null);
        out.put("san", cert != null ? cert.getSan() : null);
        out.put("sanDomains", cert == null || cert.getSanDomains() == null ? List.of() : Arrays.asList(cert.getSanDomains()));
        out.put("validFrom", cert != null ? cert.getValidFrom() : null);
        out.put("validTo", cert != null ? cert.getValidTo() : null);
        out.put("issuer", cert != null ? cert.getIssuer() : null);
        out.put("serialNumber", cert != null ? cert.getSerialNumber() : null);
        out.put("fingerprintSha256", cert != null ? cert.getFingerprintSha256() : null);

        return out;
    }
}
