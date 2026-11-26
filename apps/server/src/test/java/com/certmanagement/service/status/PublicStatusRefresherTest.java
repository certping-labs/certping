// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import com.certmanagement.dto.status.StatusSummary;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PublicStatusRefresherTest {

    private static final URI NOTIFIER = URI.create("http://certping-notifier:8080/actuator/health/status");
    private static final URI AGENT = URI.create("http://certping-agent/actuator/health/status");
    private static final Duration DEADLINE = Duration.ofMillis(300);

    private final PublicStatusBoard board = new PublicStatusBoard(new MutableClock(Instant.parse("2026-10-16T12:00:00Z")), java.time.Duration.ZERO);
    private final DatabaseCheck database = mock(DatabaseCheck.class);
    private final HealthGroupProbe probe = mock(HealthGroupProbe.class);
    private final CountDownLatch release = new CountDownLatch(1);
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private ExecutorService checks = Executors.newFixedThreadPool(3);
    private PublicStatusRefresher refresher = refresher(checks);

    @BeforeEach
    void captureLogs() {
        logs.start();
        refresherLogger().addAppender(logs);
    }

    @AfterEach
    void shutdown() {
        refresherLogger().detachAppender(logs);
        release.countDown();
        refresher.shutdown();
    }

    @Test
    void aCheckCancelledBeforeItStartedDoesNotBlockLaterRounds() throws Exception {
        refresher.shutdown();
        checks = Executors.newSingleThreadExecutor();
        refresher = refresher(checks);
        CountDownLatch occupied = new CountDownLatch(1);
        checks.submit(() -> {
            occupied.countDown();
            awaitIgnoringInterrupts(release);
        });
        assertThat(occupied.await(1, TimeUnit.SECONDS)).isTrue();
        when(database.answers()).thenReturn(true);
        when(probe.isUp(any())).thenReturn(true);

        refresher.refresh();
        assertThat(statuses()).containsExactly("major_outage", "partial_outage", "partial_outage");

        release.countDown();
        refresher.refresh();

        assertThat(statuses()).containsOnly("operational");
        verify(database, times(1)).answers();
        verify(probe, times(2)).isUp(any());
    }

    @Test
    void eachFailedCheckLogsOneWarningWithItsKindAndNothingInternal() throws Exception {
        when(database.answers()).thenThrow(new SQLException("jdbc:postgresql://internal-db refused"));
        when(probe.isUp(NOTIFIER)).thenReturn(false);
        when(probe.isUp(AGENT)).thenAnswer(invocation -> {
            release.await();
            return true;
        });

        refresher.refresh();

        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.WARN)
                .extracting(ILoggingEvent::getFormattedMessage)
                .containsExactlyInAnyOrder(
                        "Public status check of api failed: error SQLException",
                        "Public status check of notifications failed: not up",
                        "Public status check of certificates failed: timeout");
    }

    @Test
    void passingChecksLogNothing() throws Exception {
        when(database.answers()).thenReturn(true);
        when(probe.isUp(any())).thenReturn(true);

        refresher.refresh();

        assertThat(logs.list).filteredOn(event -> event.getLevel().isGreaterOrEqual(Level.WARN)).isEmpty();
    }

    private PublicStatusRefresher refresher(ExecutorService executor) {
        return new PublicStatusRefresher(board, database, probe, "http://certping-notifier:8080",
                "http://certping-agent/", DEADLINE, executor);
    }

    private static Logger refresherLogger() {
        return (Logger) LoggerFactory.getLogger(PublicStatusRefresher.class);
    }

    @Test
    void aRoundChecksEachComponentOnceAgainstItsHealthGroup() throws SQLException {
        when(database.answers()).thenReturn(true);
        when(probe.isUp(NOTIFIER)).thenReturn(true);
        when(probe.isUp(AGENT)).thenReturn(false);

        refresher.refresh();

        verify(database).answers();
        verify(probe).isUp(NOTIFIER);
        verify(probe).isUp(AGENT);
        assertThat(statuses()).containsExactly("operational", "operational", "partial_outage");
    }

    @Test
    void withoutAMailServerTheNotifierIsNotCheckedAndTheComponentIsLeftOut() throws SQLException {
        PublicStatusBoard noMail = new PublicStatusBoard(new MutableClock(Instant.parse("2026-10-16T12:00:00Z")),
                Duration.ZERO, "");
        PublicStatusRefresher noMailRefresher = new PublicStatusRefresher(noMail, database, probe,
                "http://certping-notifier:8080", "http://certping-agent/", DEADLINE,
                Executors.newFixedThreadPool(3));
        when(database.answers()).thenReturn(true);
        when(probe.isUp(AGENT)).thenReturn(true);
        try {
            noMailRefresher.refresh();
        } finally {
            noMailRefresher.shutdown();
        }

        verify(probe, times(0)).isUp(NOTIFIER);
        verify(probe).isUp(AGENT);
        assertThat(noMail.summary().orElseThrow().components())
                .extracting(StatusSummary.Component::id, StatusSummary.Component::status)
                .containsExactly(org.assertj.core.groups.Tuple.tuple("api", "operational"),
                        org.assertj.core.groups.Tuple.tuple("certificates", "operational"));
    }

    @Test
    void aCheckThatThrowsIsAFailureAndTheOthersStillCount() throws SQLException {
        when(database.answers()).thenThrow(new SQLException("jdbc:postgresql://internal-db"));
        when(probe.isUp(AGENT)).thenThrow(new IllegalStateException("http://certping-agent"));
        when(probe.isUp(NOTIFIER)).thenReturn(true);

        refresher.refresh();

        assertThat(statuses()).containsExactly("major_outage", "operational", "partial_outage");
    }

    @Test
    void theChecksRunInParallelUnderOneDeadline() throws SQLException {
        when(database.answers()).thenAnswer(invocation -> pause(DEADLINE.dividedBy(2)));
        when(probe.isUp(any())).thenAnswer(invocation -> pause(DEADLINE.dividedBy(2)));

        long started = System.nanoTime();
        refresher.refresh();

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(DEADLINE);
        assertThat(statuses()).containsOnly("operational");
    }

    @Test
    void aCheckPastTheDeadlineFailsAndIsInterrupted() throws Exception {
        CountDownLatch interrupted = new CountDownLatch(1);
        when(database.answers()).thenReturn(true);
        when(probe.isUp(NOTIFIER)).thenReturn(true);
        when(probe.isUp(AGENT)).thenAnswer(invocation -> {
            try {
                release.await();
            } catch (InterruptedException e) {
                interrupted.countDown();
            }
            return true;
        });

        long started = System.nanoTime();
        refresher.refresh();

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(DEADLINE.multipliedBy(3));
        assertThat(statuses()).containsExactly("operational", "operational", "partial_outage");
        assertThat(interrupted.await(1, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void aCheckThatIgnoresTheInterruptFailsTheNextRoundWithoutAnotherCall() throws Exception {
        when(database.answers()).thenReturn(true);
        when(probe.isUp(NOTIFIER)).thenReturn(true);
        when(probe.isUp(AGENT)).thenAnswer(invocation -> {
            awaitIgnoringInterrupts(release);
            return true;
        });

        refresher.refresh();
        long started = System.nanoTime();
        refresher.refresh();

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(DEADLINE);
        verify(probe, times(1)).isUp(AGENT);
        verify(probe, times(2)).isUp(NOTIFIER);
        assertThat(statuses()).containsExactly("operational", "operational", "partial_outage");
    }

    @Test
    void startingCompletesTheFirstRoundBeforeReturningAndStoppingEndsTheSchedule() throws SQLException {
        when(database.answers()).thenReturn(true);
        when(probe.isUp(any())).thenReturn(true);

        refresher.start();
        refresher.start();

        assertThat(board.summary()).isPresent();
        assertThat(refresher.isRunning()).isTrue();
        verify(database, times(1)).answers();
        verify(probe, times(2)).isUp(any());

        refresher.stop();

        assertThat(refresher.isRunning()).isFalse();
    }

    @Test
    void theHealthGroupPathIsAppendedOnce() {
        assertThat(PublicStatusRefresher.healthGroup("setting", " http://certping-agent-2// "))
                .isEqualTo(URI.create("http://certping-agent-2/actuator/health/status"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "certping-agent", "/actuator", "ftp://host", "http://", "http://a b"})
    void aBaseUrlThatCannotBeProbedFailsStartup(String baseUrl) {
        assertThatThrownBy(() -> PublicStatusRefresher.healthGroup("public-status.agent-base-url", baseUrl))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("public-status.agent-base-url");
    }

    private List<String> statuses() {
        return board.summary().orElseThrow().components().stream().map(StatusSummary.Component::status).toList();
    }

    private static boolean pause(Duration duration) throws InterruptedException {
        Thread.sleep(duration.toMillis());
        return true;
    }

    private static void awaitIgnoringInterrupts(CountDownLatch latch) {
        while (true) {
            try {
                latch.await();
                return;
            } catch (InterruptedException ignored) {
                // Stands in for a call that does not react to the cancel.
            }
        }
    }
}
