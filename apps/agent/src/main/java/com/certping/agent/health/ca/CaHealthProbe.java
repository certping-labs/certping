// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health.ca;

import com.certping.agent.model.message.CaConnectorHealth;

/**
 * One CA connector's self-report.
 *
 * <p>Adding a CA means adding an implementation and nothing else: the publisher collects every
 * bean of this type, so no registry or switch has to be edited.
 *
 * <p>Implementations must not throw. A probe that fails has still learned something worth
 * reporting — the publisher turning an exception into a missing connector would hide exactly
 * the outage the report exists to surface.
 */
public interface CaHealthProbe {

    /** Matches the {@code CaProvider} constant, e.g. {@code EJBCA}. */
    String caProvider();

    /** Never null, never throws. */
    CaConnectorHealth probe();
}
