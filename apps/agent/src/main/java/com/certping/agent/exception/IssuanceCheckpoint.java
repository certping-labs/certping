// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.exception;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.ssl.CaOrderAction;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Resume hint carried across attempts via message application properties. When an issuance
 * step crosses a billable / quota-charged boundary at the CA (LE newOrder, DigiCert
 * POST /order/certificate, etc.) and a downstream step then fails Retryably, the
 * service attaches one of these to its {@link RetryableAgentException}. The listener
 * propagates {@link #toAppProperties()} into the re-enqueued message; the next
 * attempt reads it back via {@link #fromMessage(InboundMessage)} and
 * resumes at {@link #step()} instead of replaying the billable step.
 *
 * <p>{@code orderCost} and {@code orderCurrency} are what the CA reported for the order when it
 * was placed. A resumed attempt never sees the order response again,
 * so they travel with the order reference and reach the result unchanged.
 *
 * <p>{@code dcv} is the validation an order relies on, so a resumed attempt can find or rewrite its records, and
 * {@code orderPlacedAt} is when the order was sent, which bounds how long it is resumed.
 *
 * <p>{@code response} is the result of a certificate already issued and stored ({@link Step#KV_STORED}) whose
 * sending failed: the next attempt only sends it again.
 *
 * <p>{@code orderAction} says whether {@code orderRef} is a new order or an order being replaced inside its
 * term, so a resumed replacement is never turned into a billed order.
 */
public record IssuanceCheckpoint(
        String provider,
        Step step,
        String orderRef,
        String acmeAccountUrl,
        String privateKeyKvPath,
        String orderCost,
        String orderCurrency,
        String dcv,
        Instant orderPlacedAt,
        String response,
        CaOrderAction orderAction) {

    /** A checkpoint with no reported order cost. */
    public IssuanceCheckpoint(String provider, Step step, String orderRef, String acmeAccountUrl,
                              String privateKeyKvPath) {
        this(provider, step, orderRef, acmeAccountUrl, privateKeyKvPath, null, null);
    }

    public IssuanceCheckpoint(String provider, Step step, String orderRef, String acmeAccountUrl,
                              String privateKeyKvPath, String orderCost, String orderCurrency) {
        this(provider, step, orderRef, acmeAccountUrl, privateKeyKvPath, orderCost, orderCurrency, null, null);
    }

    public IssuanceCheckpoint(String provider, Step step, String orderRef, String acmeAccountUrl,
                              String privateKeyKvPath, String orderCost, String orderCurrency, String dcv,
                              Instant orderPlacedAt) {
        this(provider, step, orderRef, acmeAccountUrl, privateKeyKvPath, orderCost, orderCurrency, dcv, orderPlacedAt,
                null, null);
    }

    /** The checkpoint of a certificate issued and stored whose result, {@code response}, still has to be sent. */
    public static IssuanceCheckpoint storedResult(String provider, String response) {
        return new IssuanceCheckpoint(provider, Step.KV_STORED, null, null, null, null, null, null, null, response,
                null);
    }

    public enum Step {
        CSR_GENERATED,
        ORDER_SENT,
        ORDER_CREATED,
        ORDER_FINALIZED,
        CHAIN_DOWNLOADED,
        KV_STORED
    }

    public static final String PROP_PROVIDER            = "Checkpoint.Provider";
    public static final String PROP_STEP                = "Checkpoint.Step";
    public static final String PROP_ORDER_REF           = "Checkpoint.OrderRef";
    public static final String PROP_ACME_ACCOUNT_URL    = "Checkpoint.AcmeAccountUrl";
    public static final String PROP_PRIVATE_KEY_KV_PATH = "Checkpoint.PrivateKeyKvPath";
    public static final String PROP_ORDER_COST          = "Checkpoint.OrderCost";
    public static final String PROP_ORDER_CURRENCY      = "Checkpoint.OrderCurrency";
    public static final String PROP_DCV                 = "Checkpoint.Dcv";
    public static final String PROP_ORDER_PLACED_AT     = "Checkpoint.OrderPlacedAt";
    public static final String PROP_RESPONSE            = "Checkpoint.Response";
    public static final String PROP_ORDER_ACTION        = "Checkpoint.OrderAction";
    public static final String PROP_CREATED_AT          = "Checkpoint.CreatedAt";

    public Map<String, String> toAppProperties() {
        Map<String, String> props = new LinkedHashMap<>();
        if (provider != null)         props.put(PROP_PROVIDER, provider);
        if (step != null)             props.put(PROP_STEP, step.name());
        if (orderRef != null)         props.put(PROP_ORDER_REF, orderRef);
        if (acmeAccountUrl != null)   props.put(PROP_ACME_ACCOUNT_URL, acmeAccountUrl);
        if (privateKeyKvPath != null) props.put(PROP_PRIVATE_KEY_KV_PATH, privateKeyKvPath);
        if (orderCost != null)        props.put(PROP_ORDER_COST, orderCost);
        if (orderCurrency != null)    props.put(PROP_ORDER_CURRENCY, orderCurrency);
        if (dcv != null)              props.put(PROP_DCV, dcv);
        if (orderPlacedAt != null)    props.put(PROP_ORDER_PLACED_AT, orderPlacedAt.toString());
        if (response != null)         props.put(PROP_RESPONSE, response);
        if (orderAction != null)      props.put(PROP_ORDER_ACTION, orderAction.name());
        props.put(PROP_CREATED_AT, Instant.now().toString());
        return props;
    }

    public static Optional<IssuanceCheckpoint> fromMessage(InboundMessage m) {
        if (m == null) return Optional.empty();
        return fromProperties(m.getApplicationProperties());
    }

    /** Reads a checkpoint written by {@link #toAppProperties()}; empty without a known step. */
    public static Optional<IssuanceCheckpoint> fromProperties(Map<String, ?> p) {
        String stepStr = stringOrNull(p.get(PROP_STEP));
        if (stepStr == null) return Optional.empty();
        Step step;
        try {
            step = Step.valueOf(stepStr);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        return Optional.of(new IssuanceCheckpoint(
                stringOrNull(p.get(PROP_PROVIDER)),
                step,
                stringOrNull(p.get(PROP_ORDER_REF)),
                stringOrNull(p.get(PROP_ACME_ACCOUNT_URL)),
                stringOrNull(p.get(PROP_PRIVATE_KEY_KV_PATH)),
                stringOrNull(p.get(PROP_ORDER_COST)),
                stringOrNull(p.get(PROP_ORDER_CURRENCY)),
                stringOrNull(p.get(PROP_DCV)),
                instantOrNull(p.get(PROP_ORDER_PLACED_AT)),
                stringOrNull(p.get(PROP_RESPONSE)),
                orderActionOrNull(p.get(PROP_ORDER_ACTION))));
    }

    /**
     * Whether the CA may hold an order for the attempt (sent, whether or not its answer arrived), or its certificate
     * is stored: an attempt started over from here could order a second time.
     */
    public boolean pastBillableStep() {
        return reached(Step.ORDER_SENT);
    }

    /** True when {@code this.step} is at or past {@code target}. Null-safe (null < everything). */
    public boolean reached(Step target) {
        return step != null && step.ordinal() >= target.ordinal();
    }

    public IssuanceCheckpoint withStep(Step newStep) {
        return new IssuanceCheckpoint(provider, newStep, orderRef, acmeAccountUrl, privateKeyKvPath,
                orderCost, orderCurrency, dcv, orderPlacedAt, response, orderAction);
    }

    public IssuanceCheckpoint withOrderRef(String newOrderRef, String newAcmeAccountUrl) {
        return new IssuanceCheckpoint(provider, Step.ORDER_CREATED, newOrderRef,
                newAcmeAccountUrl, privateKeyKvPath, orderCost, orderCurrency, dcv, orderPlacedAt, response, orderAction);
    }

    public IssuanceCheckpoint withPrivateKeyKvPath(String newPath) {
        return new IssuanceCheckpoint(provider, step == null ? Step.CSR_GENERATED : step,
                orderRef, acmeAccountUrl, newPath, orderCost, orderCurrency, dcv, orderPlacedAt, response, orderAction);
    }

    /** The cost the CA reported for the order, kept for a resumed attempt. */
    public IssuanceCheckpoint withOrderCost(String newOrderCost, String newOrderCurrency) {
        return new IssuanceCheckpoint(provider, step, orderRef, acmeAccountUrl, privateKeyKvPath,
                newOrderCost, newOrderCurrency, dcv, orderPlacedAt, response, orderAction);
    }

    public IssuanceCheckpoint withDcv(String newDcv, Instant newOrderPlacedAt) {
        return new IssuanceCheckpoint(provider, step, orderRef, acmeAccountUrl, privateKeyKvPath,
                orderCost, orderCurrency, newDcv, newOrderPlacedAt, response, orderAction);
    }

    public IssuanceCheckpoint withOrderAction(CaOrderAction newOrderAction) {
        return new IssuanceCheckpoint(provider, step, orderRef, acmeAccountUrl, privateKeyKvPath,
                orderCost, orderCurrency, dcv, orderPlacedAt, response, newOrderAction);
    }

    private static String stringOrNull(Object o) {
        return o == null ? null : o.toString();
    }

    private static CaOrderAction orderActionOrNull(Object o) {
        if (o == null) {
            return null;
        }
        try {
            return CaOrderAction.valueOf(o.toString());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Instant instantOrNull(Object o) {
        if (o == null) {
            return null;
        }
        try {
            return Instant.parse(o.toString());
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
