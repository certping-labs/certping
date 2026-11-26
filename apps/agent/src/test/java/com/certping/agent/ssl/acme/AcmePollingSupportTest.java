// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.acme;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.challenge.Dns01Challenge;

import java.net.URI;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AcmePollingSupportTest {

    @Test
    void problemOf_givesTheTypeAndDetail() {
        Dns01Challenge challenge = challengeWith(problem("urn:ietf:params:acme:error:dns", "query timed out"));

        assertThat(AcmePollingSupport.problemOf(challenge))
                .isEqualTo(" (urn:ietf:params:acme:error:dns: query timed out)");
    }

    @Test
    void problemOf_withoutDetail_givesTheType() {
        Dns01Challenge challenge = challengeWith(problem("urn:ietf:params:acme:error:unauthorized", null));

        assertThat(AcmePollingSupport.problemOf(challenge)).isEqualTo(" (urn:ietf:params:acme:error:unauthorized)");
    }

    @Test
    void problemOf_withoutError_isEmpty() {
        Dns01Challenge challenge = mock(Dns01Challenge.class);
        when(challenge.getError()).thenReturn(Optional.empty());

        assertThat(AcmePollingSupport.problemOf(challenge)).isEmpty();
    }

    @Test
    void problemOf_longDetail_isTruncated() {
        Dns01Challenge challenge = challengeWith(problem("urn:ietf:params:acme:error:dns", "x".repeat(1000)));

        String problem = AcmePollingSupport.problemOf(challenge);

        assertThat(problem).hasSize(AcmePollingSupport.MAX_PROBLEM_LENGTH + " (...)".length()).endsWith("...)");
    }

    private static Dns01Challenge challengeWith(Problem problem) {
        Dns01Challenge challenge = mock(Dns01Challenge.class);
        when(challenge.getError()).thenReturn(Optional.of(problem));
        return challenge;
    }

    private static Problem problem(String type, String detail) {
        Problem problem = mock(Problem.class);
        when(problem.getType()).thenReturn(URI.create(type));
        when(problem.getDetail()).thenReturn(Optional.ofNullable(detail));
        return problem;
    }
}
