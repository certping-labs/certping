// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.testing.Transactions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Map;

import static com.certmanagement.messaging.CertSuccessFixture.REQ_ID;
import static com.certmanagement.messaging.CertSuccessFixture.RENEWED_XREF;
import static com.certmanagement.messaging.CertSuccessFixture.XREF;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * A pod stopping between the success commit and the post-commit work, then the message queue redelivering
 * the response: the redelivery writes nothing again, deploys exactly once, and publishes each
 * notification under the same request id (the notifier delivers each id once).
 */
class CertSuccessRedeliveryTest {

    private final CertSuccessFixture fixture = new CertSuccessFixture(new CrashAfterFirstCommit());

    @Test
    void issuance_crashBeforeTheDispatch_redeliveryDeploysOnceAndNotifiesOnce() throws Exception {
        CertificateEntity cert = fixture.pendingIssuance();

        assertThat(fixture.deliver(fixture.response("ISSUED", XREF))).as("crashed: abandoned").isFalse();
        assertThat(cert.getStatus()).isEqualTo("ACTIVE");
        assertThat(fixture.dispatchedDeployments).isEmpty();
        verify(fixture.publisher, never()).publish(anyString(), any(), any(), any());

        assertThat(fixture.deliver(fixture.response("ISSUED", XREF))).isTrue();
        assertThat(fixture.deliver(fixture.response("ISSUED", XREF))).as("a later duplicate").isTrue();

        verify(fixture.deployer, times(1)).dispatchForCert(any(), any(), any(), eq("AUTO_POST_ISSUANCE"));
        assertThat(publishedRequestIds("CERT_ISSUANCE_SUCCESS")).containsOnly(REQ_ID);
        verify(fixture.certificates, times(1)).save(any());
        assertThat(fixture.eventsOfType("ISSUANCE_SUCCESS")).isOne();
    }

    @Test
    void renewal_deploymentOff_crashAfterTheCommit_redeliveryTellsTheCustomerOnce() throws Exception {
        fixture.renewalInFlight();
        fixture.featuresOff.add("CERTIFICATE_DEPLOYMENT");

        assertThat(fixture.deliver(fixture.response("RENEWED", RENEWED_XREF))).isFalse();
        assertThat(fixture.eventsOfType("AUTO_DEPLOY_SKIPPED_FEATURE_OFF")).isOne();
        verify(fixture.publisher, never()).publish(anyString(), any(), any(), any());

        assertThat(fixture.deliver(fixture.response("RENEWED", RENEWED_XREF))).isTrue();

        verify(fixture.publisher, times(1)).publish(eq("CERT_RENEWAL_SUCCESS"), any(), eq(RENEWED_XREF), any());
        assertThat(publishedRequestIds(CertResponseProcessor.CERT_RENEWED_NOT_DEPLOYED))
                .containsExactly(REQ_ID + ":not-deployed");
        assertThat(fixture.eventsOfType("AUTO_DEPLOY_SKIPPED_FEATURE_OFF"))
                .as("recorded only by the delivery that applied the renewal").isOne();
        assertThat(fixture.eventsOfType("RENEWAL_SUCCESS")).isOne();
        verify(fixture.deployer, never()).dispatchForCert(any(), any(), any(), anyString());
    }

    @Test
    void renewal_crashBeforeTheDispatch_redeliveryDeploysOnce() throws Exception {
        fixture.renewalInFlight();

        assertThat(fixture.deliver(fixture.response("RENEWED", RENEWED_XREF))).isFalse();
        assertThat(fixture.deliver(fixture.response("RENEWED", RENEWED_XREF))).isTrue();
        assertThat(fixture.deliver(fixture.response("RENEWED", RENEWED_XREF))).isTrue();

        verify(fixture.deployer, times(1)).dispatchForCert(any(), any(), any(), eq("AUTO_POST_RENEWAL"));
        assertThat(publishedRequestIds("CERT_RENEWAL_SUCCESS")).containsOnly(REQ_ID);
        verify(fixture.publisher, never()).publish(eq(CertResponseProcessor.CERT_RENEWED_NOT_DEPLOYED), any(), any(), any());
        verify(fixture.schedules, times(1)).save(any());
        assertThat(fixture.eventsOfType("RENEWAL_SUCCESS")).isOne();
    }

    @SuppressWarnings("unchecked")
    private java.util.List<Object> publishedRequestIds(String action) {
        ArgumentCaptor<Map<String, Object>> fields = ArgumentCaptor.forClass(Map.class);
        verify(fixture.publisher, org.mockito.Mockito.atLeastOnce()).publish(eq(action), any(), any(), fields.capture());
        return fields.getAllValues().stream().map(map -> map.get("requestId")).toList();
    }

    /** Commits, then the first time stops before anything after the commit runs, as a killed pod would. */
    private static final class CrashAfterFirstCommit extends TransactionTemplate {

        private boolean crashed;

        CrashAfterFirstCommit() {
            super(Transactions.manager());
        }

        @Override
        public <T> T execute(TransactionCallback<T> action) {
            T result = super.execute(action);
            if (!crashed) {
                crashed = true;
                throw new IllegalStateException("pod stopped right after the commit");
            }
            return result;
        }
    }
}
