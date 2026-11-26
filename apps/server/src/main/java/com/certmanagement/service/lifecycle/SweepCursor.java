// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Where a sweep stopped, per feature and pass, so a budget-capped sweep continues on the next run
 * instead of revisiting the first organizations forever. A finished pass starts over from the
 * beginning. Kept in memory: a restart only means one extra full pass.
 */
public final class SweepCursor {

    /** The two passes of a sweep. */
    public enum Pass { PAUSE, RESUME }

    private final Map<String, Long> positions = new ConcurrentHashMap<>();

    /** A cursor that starts every pass from the first organization. */
    public static SweepCursor fromStart() {
        return new SweepCursor();
    }

    long position(String featureKey, Pass pass) {
        return positions.getOrDefault(key(featureKey, pass), 0L);
    }

    void advance(String featureKey, Pass pass, long organizationId) {
        positions.put(key(featureKey, pass), organizationId);
    }

    void finish(String featureKey, Pass pass) {
        positions.remove(key(featureKey, pass));
    }

    private static String key(String featureKey, Pass pass) {
        return featureKey + ":" + pass;
    }
}
