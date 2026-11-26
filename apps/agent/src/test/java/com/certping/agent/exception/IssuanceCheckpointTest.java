// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.ssl.CaOrderAction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IssuanceCheckpointTest {

    @Test
    void toAppProperties_fullCheckpoint_includesAllFields() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint(
                "LETS_ENCRYPT",
                IssuanceCheckpoint.Step.ORDER_CREATED,
                "https://acme/order/1",
                "https://acme/acct/2",
                "https://kv/secrets/staged");

        Map<String, String> props = cp.toAppProperties();
        assertThat(props).containsEntry(IssuanceCheckpoint.PROP_PROVIDER, "LETS_ENCRYPT");
        assertThat(props).containsEntry(IssuanceCheckpoint.PROP_STEP, "ORDER_CREATED");
        assertThat(props).containsEntry(IssuanceCheckpoint.PROP_ORDER_REF, "https://acme/order/1");
        assertThat(props).containsEntry(IssuanceCheckpoint.PROP_ACME_ACCOUNT_URL, "https://acme/acct/2");
        assertThat(props).containsEntry(IssuanceCheckpoint.PROP_PRIVATE_KEY_KV_PATH, "https://kv/secrets/staged");
        assertThat(props).containsKey(IssuanceCheckpoint.PROP_CREATED_AT);
    }

    @Test
    void toAppProperties_nullFields_omitted() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint(null, null, null, null, null);
        Map<String, String> props = cp.toAppProperties();
        assertThat(props).doesNotContainKey(IssuanceCheckpoint.PROP_PROVIDER);
        assertThat(props).doesNotContainKey(IssuanceCheckpoint.PROP_STEP);
        assertThat(props).doesNotContainKey(IssuanceCheckpoint.PROP_ORDER_REF);
        assertThat(props).containsKey(IssuanceCheckpoint.PROP_CREATED_AT);
    }

    @Test
    void fromMessage_nullMessage_returnsEmpty() {
        assertThat(IssuanceCheckpoint.fromMessage(null)).isEmpty();
    }

    @Test
    void fromMessage_noStepProperty_returnsEmpty() {
        InboundMessage m = mock(InboundMessage.class);
        when(m.getApplicationProperties()).thenReturn(new HashMap<>());
        assertThat(IssuanceCheckpoint.fromMessage(m)).isEmpty();
    }

    @Test
    void fromMessage_invalidStepValue_returnsEmpty() {
        InboundMessage m = mock(InboundMessage.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IssuanceCheckpoint.PROP_STEP, "NOT_A_REAL_STEP");
        when(m.getApplicationProperties()).thenReturn(props);
        assertThat(IssuanceCheckpoint.fromMessage(m)).isEmpty();
    }

    @Test
    void fromMessage_validStep_returnsParsedCheckpoint() {
        InboundMessage m = mock(InboundMessage.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IssuanceCheckpoint.PROP_PROVIDER, "LETS_ENCRYPT");
        props.put(IssuanceCheckpoint.PROP_STEP, "ORDER_CREATED");
        props.put(IssuanceCheckpoint.PROP_ORDER_REF, "https://acme/order/9");
        props.put(IssuanceCheckpoint.PROP_ACME_ACCOUNT_URL, "https://acme/acct/8");
        props.put(IssuanceCheckpoint.PROP_PRIVATE_KEY_KV_PATH, "https://kv/secrets/key");
        when(m.getApplicationProperties()).thenReturn(props);

        Optional<IssuanceCheckpoint> result = IssuanceCheckpoint.fromMessage(m);
        assertThat(result).isPresent();
        assertThat(result.get().provider()).isEqualTo("LETS_ENCRYPT");
        assertThat(result.get().step()).isEqualTo(IssuanceCheckpoint.Step.ORDER_CREATED);
        assertThat(result.get().orderRef()).isEqualTo("https://acme/order/9");
        assertThat(result.get().acmeAccountUrl()).isEqualTo("https://acme/acct/8");
        assertThat(result.get().privateKeyKvPath()).isEqualTo("https://kv/secrets/key");
    }

    @Test
    void fromMessage_missingOptionalFields_returnsCheckpointWithNulls() {
        InboundMessage m = mock(InboundMessage.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IssuanceCheckpoint.PROP_STEP, "CSR_GENERATED");
        when(m.getApplicationProperties()).thenReturn(props);

        Optional<IssuanceCheckpoint> result = IssuanceCheckpoint.fromMessage(m);
        assertThat(result).isPresent();
        assertThat(result.get().step()).isEqualTo(IssuanceCheckpoint.Step.CSR_GENERATED);
        assertThat(result.get().provider()).isNull();
        assertThat(result.get().orderRef()).isNull();
        assertThat(result.get().acmeAccountUrl()).isNull();
        assertThat(result.get().privateKeyKvPath()).isNull();
    }

    @Test
    void reached_nullStep_returnsFalse() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("p", null, null, null, null);
        assertThat(cp.reached(IssuanceCheckpoint.Step.CSR_GENERATED)).isFalse();
    }

    @Test
    void reached_sameStep_returnsTrue() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("p", IssuanceCheckpoint.Step.ORDER_CREATED, null, null, null);
        assertThat(cp.reached(IssuanceCheckpoint.Step.ORDER_CREATED)).isTrue();
    }

    @Test
    void reached_pastStep_returnsTrue() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("p", IssuanceCheckpoint.Step.KV_STORED, null, null, null);
        assertThat(cp.reached(IssuanceCheckpoint.Step.ORDER_CREATED)).isTrue();
    }

    @Test
    void reached_beforeStep_returnsFalse() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("p", IssuanceCheckpoint.Step.CSR_GENERATED, null, null, null);
        assertThat(cp.reached(IssuanceCheckpoint.Step.ORDER_FINALIZED)).isFalse();
    }

    @Test
    void withStep_returnsNewCheckpointPreservingOtherFields() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("LE",
                IssuanceCheckpoint.Step.CSR_GENERATED, "ref", "acct", "kv");
        IssuanceCheckpoint updated = cp.withStep(IssuanceCheckpoint.Step.ORDER_FINALIZED);
        assertThat(updated.step()).isEqualTo(IssuanceCheckpoint.Step.ORDER_FINALIZED);
        assertThat(updated.provider()).isEqualTo("LE");
        assertThat(updated.orderRef()).isEqualTo("ref");
        assertThat(updated.acmeAccountUrl()).isEqualTo("acct");
        assertThat(updated.privateKeyKvPath()).isEqualTo("kv");
    }

    @Test
    void withOrderRef_setsStepToOrderCreated() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("LE",
                IssuanceCheckpoint.Step.CSR_GENERATED, null, null, "kv");
        IssuanceCheckpoint updated = cp.withOrderRef("new-ref", "new-acct");
        assertThat(updated.step()).isEqualTo(IssuanceCheckpoint.Step.ORDER_CREATED);
        assertThat(updated.orderRef()).isEqualTo("new-ref");
        assertThat(updated.acmeAccountUrl()).isEqualTo("new-acct");
        assertThat(updated.privateKeyKvPath()).isEqualTo("kv");
    }

    @Test
    void withPrivateKeyKvPath_nullStep_defaultsToCsrGenerated() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("LE", null, null, null, null);
        IssuanceCheckpoint updated = cp.withPrivateKeyKvPath("path");
        assertThat(updated.step()).isEqualTo(IssuanceCheckpoint.Step.CSR_GENERATED);
        assertThat(updated.privateKeyKvPath()).isEqualTo("path");
    }

    @Test
    void withPrivateKeyKvPath_preservesExistingStep() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("LE",
                IssuanceCheckpoint.Step.ORDER_CREATED, "ref", "acct", null);
        IssuanceCheckpoint updated = cp.withPrivateKeyKvPath("kv");
        assertThat(updated.step()).isEqualTo(IssuanceCheckpoint.Step.ORDER_CREATED);
        assertThat(updated.privateKeyKvPath()).isEqualTo("kv");
        assertThat(updated.orderRef()).isEqualTo("ref");
    }

    @Test
    void orderCost_survivesThePropertiesRoundTrip() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED,
                "12345", null, "kv").withOrderCost("210.00", "USD");
        InboundMessage m = mock(InboundMessage.class);
        when(m.getApplicationProperties()).thenReturn(new HashMap<>(cp.toAppProperties()));

        IssuanceCheckpoint read = IssuanceCheckpoint.fromMessage(m).orElseThrow();
        assertThat(read.orderCost()).isEqualTo("210.00");
        assertThat(read.orderCurrency()).isEqualTo("USD");
        assertThat(read.orderRef()).isEqualTo("12345");
    }

    @Test
    void orderCost_absentFromAnOlderAgentsProperties_isNull() {
        InboundMessage m = mock(InboundMessage.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IssuanceCheckpoint.PROP_STEP, "ORDER_CREATED");
        props.put(IssuanceCheckpoint.PROP_ORDER_REF, "12345");
        when(m.getApplicationProperties()).thenReturn(props);

        IssuanceCheckpoint read = IssuanceCheckpoint.fromMessage(m).orElseThrow();
        assertThat(read.orderCost()).isNull();
        assertThat(read.orderCurrency()).isNull();
    }

    @Test
    void replacement_keepsItsOrderActionThroughTheMessage() {
        IssuanceCheckpoint sent = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_SENT, "12345", null,
                "kv").withDcv("{}", Instant.parse("2026-10-20T00:00:00Z")).withOrderAction(CaOrderAction.REPLACEMENT);
        InboundMessage message = mock(InboundMessage.class);
        when(message.getApplicationProperties()).thenReturn(new HashMap<>(sent.toAppProperties()));

        IssuanceCheckpoint read = IssuanceCheckpoint.fromMessage(message).orElseThrow();

        assertThat(read.orderAction()).isEqualTo(CaOrderAction.REPLACEMENT);
        IssuanceCheckpoint accepted = read.withOrderRef("12345", null);
        assertThat(accepted.orderAction()).isEqualTo(CaOrderAction.REPLACEMENT);
    }

    @Test
    void pastBillableStep_onceAnyCaMayHoldAnOrderOrTheCertificateIsStored() {
        assertThat(new IssuanceCheckpoint("LETS_ENCRYPT", IssuanceCheckpoint.Step.CSR_GENERATED, null, null, "kv")
                .pastBillableStep()).isFalse();
        assertThat(new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_SENT, null, null, "kv")
                .pastBillableStep()).isTrue();
        assertThat(new IssuanceCheckpoint("LETS_ENCRYPT", IssuanceCheckpoint.Step.ORDER_CREATED, "u", "a", "kv")
                .pastBillableStep()).isTrue();
        assertThat(new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_FINALIZED, "7", null, "kv")
                .pastBillableStep()).isTrue();
        assertThat(IssuanceCheckpoint.storedResult("GLOBALSIGN", "{}").pastBillableStep()).isTrue();
    }

    @Test
    void fromProperties_readsWhatToAppPropertiesWrote() {
        IssuanceCheckpoint written = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED, "999",
                null, "kv", "12.00", "USD").withOrderAction(CaOrderAction.REPLACEMENT);

        assertThat(IssuanceCheckpoint.fromProperties(written.toAppProperties())).contains(written);
        assertThat(IssuanceCheckpoint.fromProperties(Map.of())).isEmpty();
    }

    @Test
    void storedResult_carriesTheResponseThroughTheMessageAndEveryCopy() {
        IssuanceCheckpoint stored = IssuanceCheckpoint.storedResult("LETS_ENCRYPT", "{\"status\":\"ISSUED\"}");
        InboundMessage message = mock(InboundMessage.class);
        when(message.getApplicationProperties()).thenReturn(new HashMap<>(stored.toAppProperties()));

        IssuanceCheckpoint read = IssuanceCheckpoint.fromMessage(message).orElseThrow();

        assertThat(read.step()).isEqualTo(IssuanceCheckpoint.Step.KV_STORED);
        assertThat(read.response()).isEqualTo("{\"status\":\"ISSUED\"}");
        assertThat(read.withStep(IssuanceCheckpoint.Step.KV_STORED).response()).isEqualTo(read.response());
        assertThat(new IssuanceCheckpoint("LE", IssuanceCheckpoint.Step.ORDER_CREATED, "ref", "acct", "kv")
                .toAppProperties()).doesNotContainKey(IssuanceCheckpoint.PROP_RESPONSE);
    }

    @Test
    void orderCost_nullIsLeftOutOfTheProperties() {
        Map<String, String> props = new IssuanceCheckpoint("LE", IssuanceCheckpoint.Step.ORDER_CREATED,
                "ref", "acct", "kv").toAppProperties();
        assertThat(props).doesNotContainKeys(IssuanceCheckpoint.PROP_ORDER_COST, IssuanceCheckpoint.PROP_ORDER_CURRENCY);
    }

    @Test
    void orderCost_isKeptByEveryOtherCopy() {
        IssuanceCheckpoint cp = new IssuanceCheckpoint("DIGICERT", IssuanceCheckpoint.Step.ORDER_CREATED,
                "12345", null, null, "210.00", "USD");
        for (IssuanceCheckpoint copy : List.of(cp.withStep(IssuanceCheckpoint.Step.ORDER_FINALIZED),
                cp.withOrderRef("12345", null), cp.withPrivateKeyKvPath("kv"))) {
            assertThat(copy.orderCost()).isEqualTo("210.00");
            assertThat(copy.orderCurrency()).isEqualTo("USD");
        }
    }

    @Test
    void step_enumValuesAreOrderedAsExpected() {
        // Lock the ordering used by reached()
        assertThat(IssuanceCheckpoint.Step.CSR_GENERATED.ordinal())
                .isLessThan(IssuanceCheckpoint.Step.ORDER_CREATED.ordinal());
        assertThat(IssuanceCheckpoint.Step.ORDER_CREATED.ordinal())
                .isLessThan(IssuanceCheckpoint.Step.ORDER_FINALIZED.ordinal());
        assertThat(IssuanceCheckpoint.Step.ORDER_FINALIZED.ordinal())
                .isLessThan(IssuanceCheckpoint.Step.CHAIN_DOWNLOADED.ordinal());
        assertThat(IssuanceCheckpoint.Step.CHAIN_DOWNLOADED.ordinal())
                .isLessThan(IssuanceCheckpoint.Step.KV_STORED.ordinal());
        assertThat(IssuanceCheckpoint.Step.valueOf("KV_STORED"))
                .isEqualTo(IssuanceCheckpoint.Step.KV_STORED);
    }
}
