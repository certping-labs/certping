// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.acme;

import com.certping.agent.config.AgentProperties;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.PollableResource;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.slf4j.Logger;

import java.time.Duration;

final class AcmePollingSupport {

    private AcmePollingSupport() {
    }

    /** Longest CA problem text kept in a failure message. */
    static final int MAX_PROBLEM_LENGTH = 300;

    /**
     * The CA's reason the challenge failed, such as {@code urn:ietf:params:acme:error:dns: query timed out}, as
     * {@code " (type: detail)"}, or empty when it gave none.
     */
    static String problemOf(Challenge challenge) {
        return challenge.getError().map(problem -> {
            String text = problem.getType() + problem.getDetail().map(detail -> ": " + detail).orElse("");
            return " (" + (text.length() > MAX_PROBLEM_LENGTH ? text.substring(0, MAX_PROBLEM_LENGTH) + "..." : text)
                    + ")";
        }).orElse("");
    }

    static Status waitForChallengeCompletion(Dns01Challenge challenge, AgentProperties.ChallengeProperties cfg)
            throws AcmeException, InterruptedException {
        Status challengeStatus = challenge.getStatus();
        if (challengeStatus != Status.VALID && challengeStatus != Status.INVALID) {
            challengeStatus = challenge.waitForCompletion(pollTimeout(cfg));
        }
        return challengeStatus;
    }

    static Status waitForAuthorizationCompletion(Authorization authorization, AgentProperties.ChallengeProperties cfg)
            throws AcmeException, InterruptedException {
        Status authorizationStatus = authorization.getStatus();
        if (authorizationStatus != Status.VALID && authorizationStatus != Status.INVALID) {
            authorizationStatus = authorization.waitForCompletion(pollTimeout(cfg));
        }
        return authorizationStatus;
    }

    static Status requireValidAuthorization(
            Authorization authorization,
            String domain,
            AgentProperties.ChallengeProperties cfg,
            Logger log)
            throws AcmeException, InterruptedException {
        Status authorizationStatus = waitForAuthorizationCompletion(authorization, cfg);

        log.debug("Authorization status={} for domain {}", authorizationStatus, domain);
        return authorizationStatus;
    }

    static Status waitForOrderCompletion(Order order, AgentProperties.ChallengeProperties cfg)
            throws AcmeException, InterruptedException {
        Status orderStatus = order.getStatus();
        if (orderStatus != Status.VALID && orderStatus != Status.INVALID) {
            orderStatus = order.waitForCompletion(pollTimeout(cfg));
        }
        return orderStatus;
    }

    static Duration pollTimeout(AgentProperties.ChallengeProperties cfg) {
        long attempts = Math.max(1L, cfg.getMaxAttempts());
        long pollIntervalMs = Math.max(1L, cfg.getPollIntervalMs());
        long effectivePollMs = Math.max(pollIntervalMs, PollableResource.DEFAULT_RETRY_AFTER.toMillis());
        return Duration.ofMillis(attempts * effectivePollMs);
    }
}
