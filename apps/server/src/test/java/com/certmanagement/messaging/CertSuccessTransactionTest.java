// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.messaging.model.CertIssuanceResponse;
import com.certmanagement.testing.Transactions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.ArrayList;
import java.util.List;

import static com.certmanagement.messaging.CertSuccessFixture.ORG_ID;
import static com.certmanagement.messaging.CertSuccessFixture.PREVIOUS_XREF;
import static com.certmanagement.messaging.CertSuccessFixture.RENEWED_XREF;
import static com.certmanagement.messaging.CertSuccessFixture.XREF;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.verify;

/**
 * Issuance and renewal successes as one transaction: the feature locks come first, renewal and the CA
 * are re-read under them, and everything that reaches the message queue runs after the commit.
 */
class CertSuccessTransactionTest {

    private final CertSuccessFixture fixture = new CertSuccessFixture(Transactions.inline());

    @Test
    void issuance_takesTheRenewalAndCaLocksSortedBeforeAnyRepositoryCall() throws Exception {
        fixture.pendingIssuance();
        List<String> repositoryCallsBeforeLock = new ArrayList<>();
        doAnswer(call -> {
            repositoryCallsBeforeLock.addAll(repositoryCalls());
            return null;
        }).when(fixture.lock).lock(anyLong(), anyString());

        assertThat(fixture.deliver(fixture.response("ISSUED", XREF))).isTrue();

        assertThat(repositoryCallsBeforeLock).as("no repository is touched before the locks").isEmpty();
        InOrder order = inOrder(fixture.lock, fixture.certificates);
        order.verify(fixture.lock).lock(ORG_ID, "CERTIFICATE_RENEWAL");
        order.verify(fixture.lock).lock(ORG_ID, "LETS_ENCRYPT");
        order.verify(fixture.certificates).findByCertificateXrefAndOrganizationId(XREF, ORG_ID);
    }

    @Test
    void renewal_takesTheRenewalAndCaLocksSortedBeforeAnyRepositoryCall() throws Exception {
        fixture.renewalInFlight();
        List<String> repositoryCallsBeforeLock = new ArrayList<>();
        doAnswer(call -> {
            repositoryCallsBeforeLock.addAll(repositoryCalls());
            return null;
        }).when(fixture.lock).lock(anyLong(), anyString());

        assertThat(fixture.deliver(fixture.response("RENEWED", RENEWED_XREF))).isTrue();

        assertThat(repositoryCallsBeforeLock).isEmpty();
        InOrder order = inOrder(fixture.lock, fixture.certificates, fixture.events);
        order.verify(fixture.lock).lock(ORG_ID, "CERTIFICATE_RENEWAL");
        order.verify(fixture.lock).lock(ORG_ID, "LETS_ENCRYPT");
        order.verify(fixture.certificates).findByCertificateXrefAndOrganizationId(RENEWED_XREF, ORG_ID);
    }

    @Test
    void writesRunInsideTheTransaction_dispatchAndPublishesOutsideIt() throws Exception {
        fixture.pendingIssuance();
        List<String> outsideTransaction = new ArrayList<>();
        List<String> insideTransaction = new ArrayList<>();
        doAnswer(call -> {
            (TransactionSynchronizationManager.isActualTransactionActive() ? insideTransaction : outsideTransaction)
                    .add("certificate save");
            return call.getArgument(0);
        }).when(fixture.certificates).save(any());
        doAnswer(call -> {
            (TransactionSynchronizationManager.isActualTransactionActive() ? insideTransaction : outsideTransaction)
                    .add("dispatch");
            return null;
        }).when(fixture.deployer).dispatchForCert(any(), any(), any(), anyString());
        doAnswer(call -> {
            (TransactionSynchronizationManager.isActualTransactionActive() ? insideTransaction : outsideTransaction)
                    .add("publish " + call.getArgument(0));
            return null;
        }).when(fixture.publisher).publish(anyString(), any(), any(), any());

        assertThat(fixture.deliver(fixture.response("ISSUED", XREF))).isTrue();

        assertThat(insideTransaction).containsExactly("certificate save");
        assertThat(outsideTransaction).containsExactly("dispatch", "publish CERT_ISSUANCE_SUCCESS");
    }

    @Test
    void issuance_renewalOff_holdsTheScheduleUntilRenewalIsBackOnAndRecordsWhy() throws Exception {
        fixture.pendingIssuance();
        fixture.featuresOff.add("CERTIFICATE_RENEWAL");

        assertThat(fixture.deliver(fixture.response("ISSUED", XREF))).isTrue();

        ArgumentCaptor<RenewalScheduleEntity> saved = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(fixture.schedules).save(saved.capture());
        assertThat(saved.getValue().getEnabled()).as("held by the trigger, so it resumes by itself").isTrue();
        assertThat(saved.getValue().getLastRenewalStatus()).isEqualTo("FEATURE_HOLD");
        assertThat(saved.getValue().getNextAttemptAt()).isNotNull();
        assertThat(fixture.eventsOfType("AUTO_RENEW_SKIPPED_FEATURE_OFF")).isOne();
        assertThat(fixture.eventsOfType("ISSUANCE_SUCCESS")).isOne();
        assertThat(fixture.dispatchedDeployments).as("deployment is a separate feature").hasSize(1);
    }

    @Test
    void renewal_caOff_keepsAnAdminsDisableAutoRenewInForce() throws Exception {
        RenewalScheduleEntity schedule = fixture.renewalInFlight();
        schedule.setEnabled(false); // the org admin's DISABLE_AUTO_RENEW committed while the renewal ran
        fixture.featuresOff.add("LETS_ENCRYPT");

        assertThat(fixture.deliver(fixture.response("RENEWED", RENEWED_XREF))).isTrue();

        assertThat(schedule.getEnabled()).isFalse();
        assertThat(schedule.getCertificateXref()).isEqualTo(RENEWED_XREF);
        assertThat(fixture.eventsOfType("AUTO_RENEW_SKIPPED_FEATURE_OFF")).isOne();
        assertThat(fixture.eventsOfType("RENEWAL_SUCCESS")).isOne();
    }

    @Test
    void renewal_withEverythingOn_reEnablesTheSchedule() throws Exception {
        RenewalScheduleEntity schedule = fixture.renewalInFlight();
        schedule.setEnabled(false);

        assertThat(fixture.deliver(fixture.response("RENEWED", RENEWED_XREF))).isTrue();

        assertThat(schedule.getEnabled()).isTrue();
        assertThat(fixture.eventsOfType("AUTO_RENEW_SKIPPED_FEATURE_OFF")).isZero();
        verify(fixture.deployer).dispatchForCert(any(CertificateEntity.class), any(), eq("1"), eq("AUTO_POST_RENEWAL"));
    }

    @Test
    void successRequestId_isTheResponsesOrADeterministicFallback() {
        CertIssuanceResponse response = fixture.response("ISSUED", XREF);
        assertThat(CertResponseProcessor.successRequestId(response, XREF, "ISSUED")).isEqualTo("req-success-1");

        response.setRequestId(null);
        assertThat(CertResponseProcessor.successRequestId(response, XREF, "ISSUED"))
                .isEqualTo(CertResponseProcessor.successRequestId(response, XREF, "ISSUED"))
                .isEqualTo(XREF + ":04:AB:CD:ISSUED");
        assertThat(CertResponseProcessor.successRequestId(response, PREVIOUS_XREF, "RENEWED"))
                .isEqualTo(PREVIOUS_XREF + ":04:AB:CD:RENEWED");
    }

    private List<String> repositoryCalls() {
        List<String> calls = new ArrayList<>();
        for (Object repository : List.of(fixture.certificates, fixture.events, fixture.schedules, fixture.credConfigs,
                fixture.manualStates, fixture.cryptoMetadata, fixture.deployments)) {
            mockingDetails(repository).getInvocations().forEach(invocation -> calls.add(invocation.toString()));
        }
        return calls;
    }
}
