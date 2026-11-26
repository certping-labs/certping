// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.enums.CaProvider;
import com.certmanagement.iot.cahealth.IotCaHealthService;
import com.certmanagement.iot.certificate.IotCertificateIngestionService;
import com.certmanagement.iot.certificate.IotDeviceNudgeResultService;
import com.certmanagement.iot.messaging.IotIdentitySyncResponseHandler;
import com.certmanagement.iot.profile.CertificateProfileResponseHandler;
import com.certmanagement.iot.revocation.IotIntuneRevocationWorkflow;
import com.certmanagement.iot.revocation.IotRevocationResultService;
import com.certmanagement.iot.service.IotDeviceSourceHealthService;
import com.certmanagement.messaging.model.CertIssuanceResponse;
import com.certmanagement.messaging.security.VerifiedAgentMessage;
import com.certmanagement.repository.AlertRepository;
import com.certmanagement.repository.CertManualIssuanceStateRepository;
import com.certmanagement.repository.CertificateCryptoMetadataRepository;
import com.certmanagement.repository.CertificateEventRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.service.AlertService;
import com.certmanagement.service.FeatureFlagResolver;
import com.certmanagement.service.agent.AgentDeepHealthCheckService;
import com.certmanagement.service.agent.AgentHealthService;
import com.certmanagement.service.audit.CertificateAuditRecorder;
import com.certmanagement.service.audit.MonitoringAuditRecorder;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.DeploymentExecutionService;
import com.certmanagement.service.discovery.DiscoveryService;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.util.UUID;

import static org.mockito.Mockito.mock;

/**
 * A {@link CertResponseProcessor} over real repositories, flags and feature locks, every other collaborator
 * mocked, and the agent's answers delivered to it, for PostgreSQL tests of what a response leaves behind.
 */
public final class PostgresCertResponses {

    private PostgresCertResponses() {
    }

    /** {@code deployer} is the caller's, so it can stub what a success deploys. */
    public static CertResponseProcessor processor(CertificateRepository certificates,
                                                  CertificateCryptoMetadataRepository cryptoMetadata,
                                                  CertificateEventRepository events, RenewalScheduleRepository schedules,
                                                  DomainCredentialConfigRepository credConfigs,
                                                  CertManualIssuanceStateRepository manualStates,
                                                  CredentialReferenceRepository credentials,
                                                  DeploymentRepository deployments, DeploymentExecutionService deployer,
                                                  TransactionTemplate transactions, FeatureLifecycleLock lock,
                                                  FeatureFlagResolver resolver) {
        return new CertResponseProcessor(certificates, cryptoMetadata, events, schedules, credConfigs,
                manualStates, mock(CertIssuanceService.class), mock(NotificationPublisher.class),
                new AlertService(mock(AlertRepository.class), mock(MonitoringAuditRecorder.class)), JsonMapper.builderWithJackson2Defaults().build(),
                deployer, mock(CertDeploymentConfigService.class), credentials,
                mock(AgentHealthService.class), mock(AgentDeepHealthCheckService.class), mock(DiscoveryService.class),
                mock(IotIdentitySyncResponseHandler.class), mock(IotDeviceSourceHealthService.class),
                mock(CertificateProfileResponseHandler.class), mock(IotCertificateIngestionService.class),
                mock(IotDeviceNudgeResultService.class), mock(IotCaHealthService.class),
                mock(IotRevocationResultService.class), mock(IotIntuneRevocationWorkflow.class), transactions, lock, resolver, deployments,
                mock(CertificateAuditRecorder.class));
    }

    /** The agent reports the Let's Encrypt certificate {@code xref} issued for 90 days. */
    public static void deliverIssued(CertResponseProcessor processor, long organizationId, String xref) {
        CertIssuanceResponse response = new CertIssuanceResponse();
        response.setRequestId("req-" + xref);
        response.setOrganizationId(String.valueOf(organizationId));
        response.setCertificateXref(xref);
        response.setStatus("ISSUED");
        response.setCaProvider(CaProvider.LETS_ENCRYPT);
        response.setCertSecretHandle("https://kv.vault.azure.net/secrets/cert");
        response.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme");
        response.setSerialNumber("04:AB:CF");
        response.setValidFrom(OffsetDateTime.now().toString());
        response.setValidTo(OffsetDateTime.now().plusDays(90).toString());
        deliver(processor, organizationId, "CERT_ISSUANCE_RESPONSE", JsonMapper.builderWithJackson2Defaults().build().writeValueAsString(response));
    }

    static void deliver(CertResponseProcessor processor, long organizationId, String type, String body) {
        processor.process(type, body,
                VerifiedAgentMessage.unverified(String.valueOf(organizationId), type, "msg-" + UUID.randomUUID(),
                        OffsetDateTime.now()),
                () -> { }, () -> { });
    }
}
