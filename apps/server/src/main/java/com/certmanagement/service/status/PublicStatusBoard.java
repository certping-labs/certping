// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.status;

import com.certmanagement.dto.status.StatusSummary;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Set;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The latest public state of every component. Only {@link PublicStatusRefresher} writes it; a public
 * request reads an immutable snapshot and never reaches a dependency.
 */
@Slf4j
@Component
public class PublicStatusBoard {

    public static final Duration CHECK_INTERVAL = Duration.ofSeconds(30);
    static final Duration STALE_AFTER = CHECK_INTERVAL.multipliedBy(3);

    /**
     * How long after start a component that has never answered still counts as starting rather than
     * down. On a fresh install the notifier and the agent boot after the server; without this the first
     * screen a new user sees says issuance is delayed.
     */
    public static final Duration STARTUP_GRACE = Duration.ofMinutes(3);

    private final Clock clock;
    private final Instant startedAt;
    private final Duration startupGrace;
    private final Set<PublicComponent> shown;
    private final Set<PublicComponent> answeredOnce = EnumSet.noneOf(PublicComponent.class);
    private volatile Map<PublicComponent, ComponentReading> readings = Map.of();

    /**
     * Email notifications are reported only when this installation can send email (MAIL_HOST is
     * set, as for the deployment info): without a mail server the component would read operational
     * while no email ever goes out, so it is left out of the page instead.
     */
    @Autowired
    public PublicStatusBoard(Clock clock,
                             @Value("${public-status.startup-grace:PT3M}") Duration startupGrace,
                             @Value("${MAIL_HOST:}") String mailHost) {
        this(clock, startupGrace, mailHost != null && !mailHost.isBlank());
    }

    public PublicStatusBoard(Clock clock, Duration startupGrace, boolean emailConfigured) {
        this.clock = clock;
        this.startedAt = clock.instant();
        this.startupGrace = startupGrace;
        Set<PublicComponent> components = EnumSet.allOf(PublicComponent.class);
        if (!emailConfigured) {
            components.remove(PublicComponent.NOTIFICATIONS);
        }
        this.shown = Collections.unmodifiableSet(components);
    }

    public PublicStatusBoard(Clock clock, Duration startupGrace) {
        this(clock, startupGrace, true);
    }

    public PublicStatusBoard(Clock clock) {
        this(clock, STARTUP_GRACE);
    }

    /** Whether the page shows this component; one it leaves out is not checked either. */
    public boolean reports(PublicComponent component) {
        return shown.contains(component);
    }

    synchronized void record(PublicComponent component, boolean up) {
        if (!shown.contains(component)) {
            return;
        }
        Instant checkedAt = clock.instant();
        if (up) {
            answeredOnce.add(component);
        } else if (!answeredOnce.contains(component)
                && Duration.between(startedAt, checkedAt).compareTo(startupGrace) < 0) {
            // Still starting: a service that has not answered yet is not an outage.
            up = true;
        }
        ComponentReading previous = readings.get(component);
        ComponentReading next = previous == null
                ? ComponentReading.first(component, up, checkedAt)
                : previous.next(component, up, checkedAt);
        if (previous == null || previous.status() != next.status()) {
            log.info("Public status of {} is {}", component.id(), next.status().value());
        }
        Map<PublicComponent, ComponentReading> updated = new EnumMap<>(PublicComponent.class);
        updated.putAll(readings);
        updated.put(component, next);
        readings = Collections.unmodifiableMap(updated);
    }

    /** Empty until every reported component has completed its first check. */
    public Optional<StatusSummary> summary() {
        Map<PublicComponent, ComponentReading> snapshot = readings;
        if (!snapshot.keySet().containsAll(shown)) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        List<StatusSummary.Component> components = new ArrayList<>(snapshot.size());
        ComponentStatus worst = ComponentStatus.OPERATIONAL;
        Instant newest = Instant.MIN;
        for (PublicComponent component : shown) {
            ComponentReading reading = snapshot.get(component);
            ComponentStatus status = reported(reading, now);
            worst = status.atLeast(worst);
            newest = reading.checkedAt().isAfter(newest) ? reading.checkedAt() : newest;
            components.add(new StatusSummary.Component(component.id(), component.publicName(), status.value(),
                    rfc3339(reading.checkedAt())));
        }
        return Optional.of(new StatusSummary(
                new StatusSummary.Page(rfc3339(newest)),
                new StatusSummary.Indicator(worst.indicator(), worst.description()),
                List.copyOf(components),
                List.of(),
                List.of()));
    }

    private static ComponentStatus reported(ComponentReading reading, Instant now) {
        boolean stale = Duration.between(reading.checkedAt(), now).compareTo(STALE_AFTER) > 0;
        return stale ? reading.status().atLeast(ComponentStatus.DEGRADED_PERFORMANCE) : reading.status();
    }

    private static String rfc3339(Instant instant) {
        return DateTimeFormatter.ISO_INSTANT.format(instant.truncatedTo(ChronoUnit.SECONDS));
    }
}
