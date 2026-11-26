// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.entity.DeploymentEntity;
import com.certmanagement.enums.DeploymentStatus;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DeploymentRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeploymentTrackingServiceTest {

    @Mock private DeploymentRepository deploymentRepository;
    @Mock private CredentialReferenceRepository credentialReferenceRepository;
    @InjectMocks private DeploymentTrackingService service;

    private DeploymentEntity existing() {
        return DeploymentEntity.builder()
                .requestId("req-1")
                .organizationId(5L)
                .status(DeploymentStatus.DEPLOYING.name())
                .build();
    }

    @Test
    void createRequested_savesDeployingEntity() {
        service.createRequested("req-1", "corr-1", 5L, "cert-x", 9L, "cred-x",
                "AZURE_APP_GW", "FLOW", "kv/cert", "kv/cred", Map.of("k", "v"));

        ArgumentCaptor<DeploymentEntity> cap = ArgumentCaptor.forClass(DeploymentEntity.class);
        verify(deploymentRepository).save(cap.capture());
        DeploymentEntity saved = cap.getValue();
        assertThat(saved.getRequestId()).isEqualTo("req-1");
        assertThat(saved.getStatus()).isEqualTo(DeploymentStatus.DEPLOYING.name());
        assertThat(saved.getCertificateXref()).isEqualTo("cert-x");
        assertThat(saved.getRequestedAt()).isNotNull();
        assertThat(saved.getMetadata()).containsEntry("k", "v");
    }

    @Test
    void markPublished_present_setsPublishedAt() {
        DeploymentEntity d = existing();
        when(deploymentRepository.findByRequestId("req-1")).thenReturn(Optional.of(d));

        service.markPublished("req-1");

        assertThat(d.getPublishedAt()).isNotNull();
        verify(deploymentRepository).save(d);
    }

    @Test
    void markPublished_absent_noSave() {
        when(deploymentRepository.findByRequestId("req-1")).thenReturn(Optional.empty());
        service.markPublished("req-1");
        verify(deploymentRepository, never()).save(any());
    }

    @Test
    void markPublished_orgScoped_setsPublishedAt() {
        DeploymentEntity d = existing();
        when(deploymentRepository.findByRequestIdAndOrganizationId("req-1", 5L)).thenReturn(Optional.of(d));

        service.markPublished("req-1", 5L);

        assertThat(d.getPublishedAt()).isNotNull();
        verify(deploymentRepository).save(d);
    }

    @Test
    void markPublishFailed_setsError() {
        DeploymentEntity d = existing();
        when(deploymentRepository.findByRequestId("req-1")).thenReturn(Optional.of(d));

        service.markPublishFailed("req-1", "E1", "detail");

        assertThat(d.getStatus()).isEqualTo(DeploymentStatus.PUBLISH_FAILED.name());
        assertThat(d.getErrorCode()).isEqualTo("E1");
        assertThat(d.getErrorDetail()).isEqualTo("detail");
        assertThat(d.getCompletedAt()).isNotNull();
    }

    @Test
    void markPublishFailed_orgScoped_setsError() {
        DeploymentEntity d = existing();
        when(deploymentRepository.findByRequestIdAndOrganizationId("req-1", 5L)).thenReturn(Optional.of(d));

        service.markPublishFailed("req-1", 5L, "E2", "d2");

        assertThat(d.getStatus()).isEqualTo(DeploymentStatus.PUBLISH_FAILED.name());
        assertThat(d.getErrorCode()).isEqualTo("E2");
    }

    @Test
    void markSuccess_setsTargetAndRespondedAt() {
        DeploymentEntity d = existing();
        OffsetDateTime resp = OffsetDateTime.now().minusMinutes(1);
        when(deploymentRepository.findByRequestId("req-1")).thenReturn(Optional.of(d));

        service.markSuccess("req-1", "res-1", resp);

        assertThat(d.getStatus()).isEqualTo(DeploymentStatus.SUCCESS.name());
        assertThat(d.getTargetResourceId()).isEqualTo("res-1");
        assertThat(d.getRespondedAt()).isEqualTo(resp);
    }

    @Test
    void markSuccess_nullRespondedAt_defaultsToNow() {
        DeploymentEntity d = existing();
        when(deploymentRepository.findByRequestId("req-1")).thenReturn(Optional.of(d));

        service.markSuccess("req-1", "res-1", null);

        assertThat(d.getRespondedAt()).isNotNull();
    }

    @Test
    void markSuccess_orgScoped_setsSuccess() {
        DeploymentEntity d = existing();
        when(deploymentRepository.findByRequestIdAndOrganizationId("req-1", 5L)).thenReturn(Optional.of(d));

        service.markSuccess("req-1", 5L, "res-2", null);

        assertThat(d.getStatus()).isEqualTo(DeploymentStatus.SUCCESS.name());
        assertThat(d.getTargetResourceId()).isEqualTo("res-2");
    }

    @Test
    void markFailed_setsFailure() {
        DeploymentEntity d = existing();
        when(deploymentRepository.findByRequestId("req-1")).thenReturn(Optional.of(d));

        service.markFailed("req-1", "EF", "fail", null);

        assertThat(d.getStatus()).isEqualTo(DeploymentStatus.FAILED.name());
        assertThat(d.getErrorCode()).isEqualTo("EF");
        assertThat(d.getRespondedAt()).isNotNull();
    }

    @Test
    void markFailed_orgScoped_setsFailure() {
        DeploymentEntity d = existing();
        OffsetDateTime resp = OffsetDateTime.now();
        when(deploymentRepository.findByRequestIdAndOrganizationId("req-1", 5L)).thenReturn(Optional.of(d));

        service.markFailed("req-1", 5L, "EF2", "fail2", resp);

        assertThat(d.getStatus()).isEqualTo(DeploymentStatus.FAILED.name());
        assertThat(d.getRespondedAt()).isEqualTo(resp);
    }

    @Test
    void markFailed_aLateFailureNeverOverwritesASuccess() {
        DeploymentEntity d = existing();
        d.setStatus(DeploymentStatus.SUCCESS.name());
        when(deploymentRepository.findByRequestIdAndOrganizationId("req-1", 5L)).thenReturn(Optional.of(d));
        when(deploymentRepository.findByRequestId("req-1")).thenReturn(Optional.of(d));

        service.markFailed("req-1", 5L, "EF2", "fail2", OffsetDateTime.now());
        service.markFailed("req-1", "EF", "fail", null);

        assertThat(d.getStatus()).isEqualTo(DeploymentStatus.SUCCESS.name());
        assertThat(d.getErrorCode()).isNull();
        org.mockito.Mockito.verify(deploymentRepository, org.mockito.Mockito.never()).save(any());
    }

    @Test
    void markFailed_aTargetRefusingTheCredentialIsRecordedOnTheCredential() {
        DeploymentEntity d = existing();
        d.setDeploymentCredentialXref("cred-k8s");
        when(deploymentRepository.findByRequestIdAndOrganizationId("req-1", 5L)).thenReturn(Optional.of(d));

        service.markFailed("req-1", 5L, "DEPLOY_K8S_SECRET_UPSERT_FAILED",
                "Kubernetes secret upsert failed for namespace=web (HTTP 401, debugId=abc)", null);

        verify(credentialReferenceRepository).recordLastError(eq("cred-k8s"), eq(5L),
                startsWith("The deployment target refused this credential (HTTP 401) on "));
    }

    @Test
    void markFailed_anotherFailureLeavesTheCredentialAlone() {
        DeploymentEntity d = existing();
        d.setDeploymentCredentialXref("cred-k8s");
        when(deploymentRepository.findByRequestIdAndOrganizationId("req-1", 5L)).thenReturn(Optional.of(d));

        service.markFailed("req-1", 5L, "DEPLOY_PROVIDER_THROTTLED", "HTTP 429 from the API server", null);

        verify(credentialReferenceRepository, never()).recordLastError(anyString(), any(), anyString());
    }

    @Test
    void markSuccess_clearsARefusalRecordedOnTheCredential() {
        DeploymentEntity d = existing();
        d.setDeploymentCredentialXref("cred-k8s");
        when(deploymentRepository.findByRequestIdAndOrganizationId("req-1", 5L)).thenReturn(Optional.of(d));

        service.markSuccess("req-1", 5L, "ns/secret", null);

        verify(credentialReferenceRepository).clearLastError("cred-k8s", 5L);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "DEPLOY_F5_AUTH_FAILED, login refused, The deployment target refused this credential (DEPLOY_F5_AUTH_FAILED)",
            "DEPLOY_CREDENTIAL_INVALID, , The deployment target refused this credential (DEPLOY_CREDENTIAL_INVALID)",
            "DEPLOY_GCP_FAILED, status code: 403 Forbidden, The deployment target refused this credential (HTTP 403)",
    })
    void credentialRefusal_recognisesAuthFailures(String code, String detail, String expected) {
        assertThat(DeploymentTrackingService.credentialRefusal(code, detail)).isEqualTo(expected);
    }

    @Test
    void findByRequestId_delegatesToRepository() {
        DeploymentEntity d = existing();
        when(deploymentRepository.findByRequestId("req-1")).thenReturn(Optional.of(d));
        assertThat(service.findByRequestId("req-1")).containsSame(d);
    }
}
