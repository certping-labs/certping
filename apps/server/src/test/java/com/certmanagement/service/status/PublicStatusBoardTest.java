// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import com.certmanagement.dto.status.StatusSummary;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static com.certmanagement.service.status.PublicComponent.API;
import static com.certmanagement.service.status.PublicComponent.CERTIFICATES;
import static com.certmanagement.service.status.PublicComponent.NOTIFICATIONS;
import static org.assertj.core.api.Assertions.assertThat;

class PublicStatusBoardTest {

    private static final Instant START = Instant.parse("2026-10-16T12:00:00.750Z");

    private final MutableClock clock = new MutableClock(START);
    private final PublicStatusBoard board = new PublicStatusBoard(clock, java.time.Duration.ZERO);


    @Test
    void allUpIsOperationalWithSecondPrecisionUtcTimes() {
        recordRound(true, true, true);

        StatusSummary summary = board.summary().orElseThrow();

        assertThat(summary.status()).isEqualTo(new StatusSummary.Indicator("none", "All systems operational"));
        assertThat(summary.page().updatedAt()).isEqualTo("2026-10-16T12:00:00Z");
        assertThat(summary.components()).containsExactly(
                new StatusSummary.Component("api", "API and sign-in", "operational", "2026-10-16T12:00:00Z"),
                new StatusSummary.Component("notifications", "Email notifications", "operational",
                        "2026-10-16T12:00:00Z"),
                new StatusSummary.Component("certificates", "Certificate issuance and renewal", "operational",
                        "2026-10-16T12:00:00Z"));
        assertThat(summary.incidents()).isEmpty();
        assertThat(summary.scheduledMaintenances()).isEmpty();
    }

    @Test
    void aFirstFailedCheckIsReportedAtOnce() {
        recordRound(false, false, true);

        StatusSummary summary = board.summary().orElseThrow();

        assertThat(statusOf(summary, "api")).isEqualTo("major_outage");
        assertThat(statusOf(summary, "notifications")).isEqualTo("partial_outage");
        assertThat(summary.status()).isEqualTo(new StatusSummary.Indicator("critical", "Major system outage"));
    }

    @Test
    void oneFailureKeepsOperationalAndTheSecondInARowLeavesIt() {
        recordRound(true, true, true);

        recordRound(true, true, false);
        assertThat(statusOf(board.summary().orElseThrow(), "certificates")).isEqualTo("operational");

        recordRound(true, true, false);
        StatusSummary summary = board.summary().orElseThrow();
        assertThat(statusOf(summary, "certificates")).isEqualTo("partial_outage");
        assertThat(summary.status()).isEqualTo(new StatusSummary.Indicator("major", "Partial system outage"));
    }

    @Test
    void aSuccessBetweenFailuresResetsTheCount() {
        recordRound(true, true, true);
        recordRound(true, false, true);
        recordRound(true, true, true);
        recordRound(true, false, true);

        assertThat(statusOf(board.summary().orElseThrow(), "notifications")).isEqualTo("operational");
    }

    @Test
    void oneSuccessReturnsAFailingComponentToOperational() {
        recordRound(false, true, true);
        recordRound(false, true, true);

        recordRound(true, true, true);

        assertThat(statusOf(board.summary().orElseThrow(), "api")).isEqualTo("operational");
    }

    @Test
    void theApiDatabaseFailingIsAMajorOutage() {
        recordRound(true, true, true);
        recordRound(false, true, true);
        recordRound(false, true, true);

        assertThat(statusOf(board.summary().orElseThrow(), "api")).isEqualTo("major_outage");
    }


    @Test
    void aSnapshotOlderThanThreeIntervalsIsNeverOperational() {
        recordRound(true, true, true);

        clock.advance(PublicStatusBoard.STALE_AFTER);
        assertThat(board.summary().orElseThrow().status().indicator()).isEqualTo("none");

        clock.advance(Duration.ofSeconds(1));
        StatusSummary stale = board.summary().orElseThrow();

        assertThat(stale.components()).extracting(StatusSummary.Component::status)
                .containsOnly("degraded_performance");
        assertThat(stale.status()).isEqualTo(new StatusSummary.Indicator("minor", "Minor service disruption"));
    }

    @Test
    void aStaleOutageStaysAnOutage() {
        recordRound(false, true, true);

        clock.advance(PublicStatusBoard.STALE_AFTER.plusSeconds(1));

        StatusSummary stale = board.summary().orElseThrow();
        assertThat(statusOf(stale, "api")).isEqualTo("major_outage");
        assertThat(statusOf(stale, "notifications")).isEqualTo("degraded_performance");
    }



    @Test
    void withoutAMailServerEmailNotificationsAreLeftOutOfThePage() {
        PublicStatusBoard noMail = new PublicStatusBoard(clock, Duration.ZERO, "");
        noMail.record(API, true);
        noMail.record(NOTIFICATIONS, false);
        noMail.record(CERTIFICATES, true);

        StatusSummary summary = noMail.summary().orElseThrow();

        assertThat(noMail.reports(NOTIFICATIONS)).isFalse();
        assertThat(summary.components()).extracting(StatusSummary.Component::id)
                .containsExactly("api", "certificates");
        assertThat(summary.status()).isEqualTo(new StatusSummary.Indicator("none", "All systems operational"));
    }

    @Test
    void withoutAMailServerTheSummaryWaitsOnlyForTheOtherComponents() {
        PublicStatusBoard noMail = new PublicStatusBoard(clock, Duration.ZERO, "  ");
        noMail.record(API, true);
        assertThat(noMail.summary()).isEmpty();

        noMail.record(CERTIFICATES, true);
        assertThat(noMail.summary()).isPresent();
    }

    @Test
    void withAMailServerEmailNotificationsAreReported() {
        PublicStatusBoard withMail = new PublicStatusBoard(clock, Duration.ZERO, "smtp.example.com");
        withMail.record(API, true);
        withMail.record(CERTIFICATES, true);
        assertThat(withMail.summary()).isEmpty();

        withMail.record(NOTIFICATIONS, true);

        assertThat(withMail.reports(NOTIFICATIONS)).isTrue();
        assertThat(withMail.summary().orElseThrow().components()).extracting(StatusSummary.Component::id)
                .containsExactly("api", "notifications", "certificates");
    }

    private void recordRound(boolean api, boolean notifications, boolean certificates) {
        board.record(API, api);
        board.record(NOTIFICATIONS, notifications);
        board.record(CERTIFICATES, certificates);
    }

    private static String statusOf(StatusSummary summary, String id) {
        return summary.components().stream().filter(component -> component.id().equals(id)).findFirst()
                .orElseThrow().status();
    }

    @Test
    void aComponentThatHasNotAnsweredYetIsStartingNotDownDuringTheGrace() {
        MutableClock startClock = new MutableClock(Instant.parse("2026-10-27T07:00:00Z"));
        PublicStatusBoard starting = new PublicStatusBoard(startClock, java.time.Duration.ofMinutes(3));
        for (PublicComponent component : PublicComponent.values()) {
            starting.record(component, component == PublicComponent.API);
        }
        assertThat(starting.summary().orElseThrow().components())
                .allSatisfy(c -> assertThat(c.status()).isEqualTo("operational"));

        startClock.advance(java.time.Duration.ofMinutes(4));
        for (PublicComponent component : PublicComponent.values()) {
            starting.record(component, component == PublicComponent.API);
        }
        startClock.advance(java.time.Duration.ofSeconds(30));
        for (PublicComponent component : PublicComponent.values()) {
            starting.record(component, component == PublicComponent.API);
        }
        assertThat(starting.summary().orElseThrow().components())
                .filteredOn(c -> !c.id().equals("api"))
                .allSatisfy(c -> assertThat(c.status()).isNotEqualTo("operational"));
    }
}
