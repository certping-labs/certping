// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

import com.certmanagement.iot.certificate.IotDeviceCertificate;
import com.certmanagement.iot.certificate.IotDeviceCertificateRepository;
import com.certmanagement.iot.config.IotRevocationProperties;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.repository.IotDeviceSourceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import com.certmanagement.messaging.model.AgentErrorMessage;
import com.certmanagement.service.OrgTypeResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotIntuneRevocationWorkflowTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:00:00Z"), ZoneOffset.UTC);
    private static final OffsetDateTime NOW = OffsetDateTime.now(CLOCK);

    @Mock private IotIntuneRevocationPollStateRepository stateRepository;
    @Mock private IotCertificateRevocationRepository revocationRepository;
    @Mock private IotDeviceCertificateRepository certificateRepository;
    @Mock private IotDeviceSourceRepository sourceRepository;
    @Mock private IotDeviceEventService eventService;
    @Mock private OrgTypeResolver orgTypeResolver;
    private IotRevocationProperties properties;
    private IotIntuneRevocationWorkflow workflow;

    @BeforeEach
    void setUp() {
        properties = new IotRevocationProperties();
        workflow = new IotIntuneRevocationWorkflow(
                stateRepository, revocationRepository, certificateRepository,
                sourceRepository, eventService, orgTypeResolver, properties, CLOCK);
    }

    @Test
    void downloadedEjbcaRequestBecomesDurableRevocationOperation() {
        IotDeviceSource source = source();
        IotIntuneRevocationPollState state = state();
        IotDeviceCertificate certificate = certificate();
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", 42L))
                .thenReturn(Optional.of(source));
        when(stateRepository.findByDeviceSourceIdForUpdate(3L)).thenReturn(Optional.of(state));
        when(revocationRepository.findByDeviceSourceIdAndRequestContextHash(
                org.mockito.ArgumentMatchers.eq(3L), any()))
                .thenReturn(Optional.empty());
        when(certificateRepository.findAllByOrganizationIdAndIssuerDnAndSerialNumber(
                42L, "CN=Issuer", "abc")).thenReturn(List.of(certificate));
        workflow.handlePollResult(pollResult(request()));

        ArgumentCaptor<IotCertificateRevocation> saved =
                ArgumentCaptor.forClass(IotCertificateRevocation.class);
        verify(revocationRepository).save(saved.capture());
        assertThat(saved.getValue().getSource()).isEqualTo(IotCertificateRevocationSource.INTUNE);
        assertThat(saved.getValue().getStatus()).isEqualTo(IotCertificateRevocationStatus.PENDING);
        assertThat(saved.getValue().getRequestContext()).isEqualTo("ctx-1");
        assertThat(saved.getValue().getRequestContextHash()).hasSize(64);
        assertThat(certificate.getStatus()).isEqualTo("REVOCATION_PENDING");
        assertThat(state.getStatus()).isEqualTo(IotIntuneRevocationPollStatus.PROCESSING);
        verify(eventService).recordCertificateUnderWorkflowLock(any(), any(), any(), any(), any(), any(),
                any(), any(), any(), any());
    }

    @Test
    void emptyDownloadReturnsSameRowToIdleWithCooldown() {
        IotIntuneRevocationPollState state = state();
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", 42L))
                .thenReturn(Optional.of(source()));
        when(stateRepository.findByDeviceSourceIdForUpdate(3L)).thenReturn(Optional.of(state));

        workflow.handlePollResult(pollResult(null));

        assertThat(state.getStatus()).isEqualTo(IotIntuneRevocationPollStatus.IDLE);
        assertThat(state.getTransactionId()).isNull();
        assertThat(state.getNextAttemptAt()).isEqualTo(NOW.plusMinutes(65));
        verify(stateRepository).save(state);
    }

    @Test
    void redeliveredEmptyDownloadIsRetriedAfterCooldownInsteadOfBeingLost() {
        IotIntuneRevocationPollState state = state();
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", 42L))
                .thenReturn(Optional.of(source()));
        when(stateRepository.findByDeviceSourceIdForUpdate(3L)).thenReturn(Optional.of(state));
        IotIntuneRevocationPollResult result = pollResult(null);
        result.setRedelivered(true);

        workflow.handlePollResult(result);

        assertThat(state.getStatus()).isEqualTo(IotIntuneRevocationPollStatus.FAILED);
        assertThat(state.getTransactionId()).isEqualTo("tx-1");
        assertThat(state.getNextAttemptAt()).isEqualTo(NOW.plusMinutes(65));
        assertThat(state.getLastErrorCode()).isEqualTo("INTUNE_POLL_REDELIVERED_EMPTY");
    }

    @Test
    void laterPollAttemptReturningEmptyIsNotMistakenForAnEmptyQueue() {
        IotIntuneRevocationPollState state = state();
        state.setAttemptCount(2);
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", 42L))
                .thenReturn(Optional.of(source()));
        when(stateRepository.findByDeviceSourceIdForUpdate(3L)).thenReturn(Optional.of(state));
        IotIntuneRevocationPollResult result = pollResult(null);
        result.setRequestId("tx-1:poll:2");
        result.setDispatchAttempt(2);

        workflow.handlePollResult(result);

        assertThat(state.getStatus()).isEqualTo(IotIntuneRevocationPollStatus.FAILED);
        assertThat(state.getLastErrorCode()).isEqualTo("INTUNE_POLL_REDELIVERED_EMPTY");
    }

    @Test
    void lateAgentErrorCannotRewindACompletedPoll() {
        IotIntuneRevocationPollState state = state();
        state.setStatus(IotIntuneRevocationPollStatus.PROCESSING);
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", 42L))
                .thenReturn(Optional.of(source()));
        when(stateRepository.findByDeviceSourceIdForUpdate(3L)).thenReturn(Optional.of(state));
        AgentErrorMessage error = new AgentErrorMessage();
        error.setOrganizationId("42");
        error.setSourceXref("src-1");
        error.setCorrelationId("tx-1");
        error.setRequestId("tx-1:poll:1");

        workflow.handleAgentError(error, false);

        assertThat(state.getStatus()).isEqualTo(IotIntuneRevocationPollStatus.PROCESSING);
        org.mockito.Mockito.verify(stateRepository, org.mockito.Mockito.never()).save(any());
    }

    @Test
    void fastPollResponseIsNotOverwrittenByDispatchFinalization() {
        IotIntuneRevocationPollState state = state();
        state.setStatus(IotIntuneRevocationPollStatus.PROCESSING);
        when(stateRepository.findByIdForUpdate(5L)).thenReturn(Optional.of(state));

        workflow.markDispatched(5L, 1, IotIntuneRevocationWorkflow.WorkType.POLL);

        assertThat(state.getStatus()).isEqualTo(IotIntuneRevocationPollStatus.PROCESSING);
        org.mockito.Mockito.verify(stateRepository, org.mockito.Mockito.never()).save(any());
    }

    @Test
    void uploadUsesMicrosoftNumericResultCodes() {
        IotIntuneRevocationPollState state = state();
        state.setStatus(IotIntuneRevocationPollStatus.PENDING_UPLOAD);
        when(stateRepository.claimNextDue(NOW)).thenReturn(Optional.of(state));
        when(sourceRepository.findById(3L)).thenReturn(Optional.of(source()));
        when(orgTypeResolver.resolve(42L)).thenReturn("B2B");
        IotCertificateRevocation confirmed = intuneOperation(
                "ctx-ok", IotCertificateRevocationStatus.CONFIRMED, null);
        IotCertificateRevocation missing = intuneOperation(
                "ctx-missing", IotCertificateRevocationStatus.FAILED,
                "CERTIFICATE_NOT_FOUND");
        when(revocationRepository.findAllByDeviceSourceIdAndIntuneTransactionIdOrderById(
                3L, "tx-1")).thenReturn(List.of(confirmed, missing));

        IotIntuneRevocationWorkflow.Work work = workflow.claimNext().orElseThrow();

        assertThat(work.uploadCommand().getRequestId()).isEqualTo("tx-1:upload:2");
        assertThat(work.uploadCommand().getResults()).extracting(
                IotIntuneRevocationUploadCommand.Result::errorCode)
                .containsExactly("0", "4004");
    }

    @Test
    void separateIntuneContextsForSameCertificateAreBothPreserved() {
        IotIntuneRevocationPollState state = state();
        IotDeviceCertificate certificate = certificate();
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", 42L))
                .thenReturn(Optional.of(source()));
        when(stateRepository.findByDeviceSourceIdForUpdate(3L)).thenReturn(Optional.of(state));
        when(revocationRepository.findByDeviceSourceIdAndRequestContextHash(
                org.mockito.ArgumentMatchers.eq(3L), any())).thenReturn(Optional.empty());
        when(certificateRepository.findAllByOrganizationIdAndIssuerDnAndSerialNumber(
                42L, "CN=Issuer", "abc")).thenReturn(List.of(certificate));
        IotIntuneRevocationPollResult.Request second = request();
        second.setRequestContext("ctx-2");
        IotIntuneRevocationPollResult result = pollResult(request());
        result.setRequests(List.of(request(), second));

        workflow.handlePollResult(result);

        ArgumentCaptor<IotCertificateRevocation> operations =
                ArgumentCaptor.forClass(IotCertificateRevocation.class);
        verify(revocationRepository, times(2)).save(operations.capture());
        assertThat(operations.getAllValues()).extracting(
                IotCertificateRevocation::getRequestContext)
                .containsExactly("ctx-1", "ctx-2");
    }

    @Test
    void reofferedUnknownOperationGetsANewCycleAndAuditIdentity() {
        IotIntuneRevocationPollState state = state();
        IotDeviceCertificate certificate = certificate();
        IotCertificateRevocation duplicate = intuneOperation(
                "ctx-1", IotCertificateRevocationStatus.OUTCOME_UNKNOWN, "RETRY_GIVE_UP");
        duplicate.setCertificateId(certificate.getId());
        duplicate.setIntuneTransactionId("tx-old");
        duplicate.setAttemptCount(8);
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", 42L))
                .thenReturn(Optional.of(source()));
        when(stateRepository.findByDeviceSourceIdForUpdate(3L)).thenReturn(Optional.of(state));
        when(revocationRepository.findByDeviceSourceIdAndRequestContextHash(eq(3L), any()))
                .thenReturn(Optional.of(duplicate));
        when(certificateRepository.findById(certificate.getId()))
                .thenReturn(Optional.of(certificate));

        workflow.handlePollResult(pollResult(request()));

        assertThat(duplicate.getIntuneTransactionId()).isEqualTo("tx-1");
        assertThat(duplicate.getStatus()).isEqualTo(IotCertificateRevocationStatus.PENDING);
        assertThat(duplicate.getAttemptCount()).isZero();
        verify(eventService).recordCertificate(any(), any(), eq("PENDING"), any(), any(), any(),
                any(), eq("tx-1"), eq(duplicate.getOperationXref()
                        + ":intune-downloaded:tx-1"), eq(NOW));
    }

    @Test
    void certificateAuthorityCertificateIsRejectedWithoutChangingItsState() {
        IotIntuneRevocationPollState state = state();
        IotDeviceCertificate certificate = certificate();
        certificate.setCertificateAuthority(true);
        when(sourceRepository.findBySourceXrefAndOrganizationId("src-1", 42L))
                .thenReturn(Optional.of(source()));
        when(stateRepository.findByDeviceSourceIdForUpdate(3L)).thenReturn(Optional.of(state));
        when(revocationRepository.findByDeviceSourceIdAndRequestContextHash(
                org.mockito.ArgumentMatchers.eq(3L), any())).thenReturn(Optional.empty());
        when(certificateRepository.findAllByOrganizationIdAndIssuerDnAndSerialNumber(
                42L, "CN=Issuer", "abc")).thenReturn(List.of(certificate));

        workflow.handlePollResult(pollResult(request()));

        ArgumentCaptor<IotCertificateRevocation> saved =
                ArgumentCaptor.forClass(IotCertificateRevocation.class);
        verify(revocationRepository).save(saved.capture());
        assertThat(saved.getValue().getStatus()).isEqualTo(IotCertificateRevocationStatus.FAILED);
        assertThat(saved.getValue().getErrorCode()).isEqualTo("IOT_CA_CERTIFICATE_NOT_REVOCABLE");
        assertThat(certificate.getStatus()).isEqualTo("ISSUED");
    }

    @Test
    void processingBatchUsesBoundedPollingAndEventuallyMovesToUpload() {
        IotIntuneRevocationPollState state = state();
        state.setStatus(IotIntuneRevocationPollStatus.PROCESSING);
        state.setRequestedAt(NOW.minusHours(1));
        when(stateRepository.claimNextDue(NOW)).thenReturn(Optional.of(state));
        when(sourceRepository.findById(3L)).thenReturn(Optional.of(source()));
        when(revocationRepository.countByDeviceSourceIdAndIntuneTransactionIdAndStatusIn(
                3L, "tx-1", List.of(IotCertificateRevocationStatus.PENDING,
                        IotCertificateRevocationStatus.DISPATCHED))).thenReturn(1L);

        IotIntuneRevocationWorkflow.Work work = workflow.claimNext().orElseThrow();

        assertThat(work.type()).isEqualTo(IotIntuneRevocationWorkflow.WorkType.SKIP);
        assertThat(state.getNextAttemptAt()).isEqualTo(NOW.plusMinutes(2));

        state.setRequestedAt(NOW.minusHours(6));
        when(stateRepository.claimNextDue(NOW)).thenReturn(Optional.of(state));
        when(revocationRepository.findAllByDeviceSourceIdAndIntuneTransactionIdOrderById(
                3L, "tx-1")).thenReturn(List.of(intuneOperation(
                        "ctx-active", IotCertificateRevocationStatus.DISPATCHED, null)));
        when(orgTypeResolver.resolve(42L)).thenReturn("B2B");

        IotIntuneRevocationWorkflow.Work upload = workflow.claimNext().orElseThrow();

        assertThat(upload.type()).isEqualTo(IotIntuneRevocationWorkflow.WorkType.UPLOAD);
        assertThat(upload.uploadCommand().getResults().getFirst().errorCode()).isEqualTo("4100");
    }

    private static IotIntuneRevocationPollResult pollResult(
            IotIntuneRevocationPollResult.Request request) {
        IotIntuneRevocationPollResult result = new IotIntuneRevocationPollResult();
        result.setOrganizationId("42");
        result.setSourceXref("src-1");
        result.setTransactionId("tx-1");
        result.setRequestId("tx-1:poll:1");
        result.setDispatchAttempt(1);
        result.setRedelivered(false);
        result.setOutcome("SUCCESS");
        result.setRequests(request == null ? List.of() : List.of(request));
        return result;
    }

    private static IotIntuneRevocationPollResult.Request request() {
        IotIntuneRevocationPollResult.Request request =
                new IotIntuneRevocationPollResult.Request();
        request.setRequestContext("ctx-1");
        request.setIssuerName("CN=Issuer");
        request.setSerialNumber("abc");
        request.setCaConfiguration("ManagementCA");
        return request;
    }

    private static IotIntuneRevocationPollState state() {
        return IotIntuneRevocationPollState.builder()
                .id(5L).organizationId(42L).deviceSourceId(3L)
                .transactionId("tx-1")
                .status(IotIntuneRevocationPollStatus.POLL_DISPATCHED)
                .attemptCount(1).nextAttemptAt(NOW).createdAt(NOW).updatedAt(NOW).build();
    }

    private static IotDeviceSource source() {
        return IotDeviceSource.builder().id(3L).organizationId(42L)
                .sourceXref("src-1").connectionProfileRef("intune-primary").build();
    }

    private static IotDeviceCertificate certificate() {
        return IotDeviceCertificate.builder().id(9L).organizationId(42L)
                .certificateXref("crt-1").enrollmentId(8L).deviceSourceId(3L).deviceId(4L)
                .caProvider("EJBCA").issuerDn("CN=Issuer").serialNumber("abc")
                .certificateAuthority(false).status("ISSUED").build();
    }

    private static IotCertificateRevocation intuneOperation(
            String context, IotCertificateRevocationStatus status, String errorCode) {
        return IotCertificateRevocation.builder().id((long) context.hashCode())
                .operationXref("op-" + context).organizationId(42L).deviceSourceId(3L)
                .source(IotCertificateRevocationSource.INTUNE).intuneTransactionId("tx-1")
                .requestContext(context).requestContextHash("a".repeat(64))
                .reason(IotRevocationReason.CESSATION_OF_OPERATION).status(status)
                .attemptCount(1).nextAttemptAt(NOW).errorCode(errorCode)
                .createdAt(NOW).updatedAt(NOW).build();
    }
}
