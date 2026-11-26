// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.transport;

import java.time.Duration;

/**
 * The pause between queue checks of one gateway long poll. It starts short, because an agent opens a new poll
 * right after it received a message and more are likely to follow, then doubles while the queue stays empty
 * up to a ceiling, so an idle agent costs a few queries per poll instead of one every half second. A found
 * message ends the poll, and the next poll starts short again. Not thread safe: one per poll.
 */
public final class PollBackoff {

    private final long minMillis;
    private final long maxMillis;
    private long nextMillis;

    public PollBackoff(Duration min, Duration max) {
        this.minMillis = Math.max(1, min.toMillis());
        this.maxMillis = Math.max(this.minMillis, max.toMillis());
        this.nextMillis = this.minMillis;
    }

    /** The pause before the next check; each call doubles the following one up to the ceiling. */
    public long nextPauseMillis() {
        long pause = nextMillis;
        nextMillis = Math.min(maxMillis, nextMillis * 2);
        return pause;
    }

    /** Back to the shortest pause, after a message was found. */
    public void reset() {
        nextMillis = minMillis;
    }
}
