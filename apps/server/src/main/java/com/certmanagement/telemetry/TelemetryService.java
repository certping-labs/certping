// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.telemetry;

import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DiscoveredCertRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserMfaRepository;
import com.certmanagement.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.info.BuildProperties;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.time.Clock;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;

/**
 * Builds and, when the operator opted in, sends the usage report. {@link #preview()} is the same
 * report the job would send, so an administrator can read it before turning telemetry on. A failed
 * send is logged at debug and never retried early: the report is not important enough to make noise.
 */
@Service
@Slf4j
public class TelemetryService {

    private final TelemetryProperties properties;
    private final InstallationIdentity installation;
    private final ObjectProvider<BuildProperties> buildProperties;
    private final JdbcTemplate jdbc;
    private final OrganizationRepository organizations;
    private final UserRepository users;
    private final UserMfaRepository userMfa;
    private final CertificateRepository certificates;
    private final DiscoveredCertRepository discoveredCerts;
    private final DomainCredentialConfigRepository credentialConfigs;
    private final Clock clock;
    private final RestClient http;

    static final String JOB = "telemetry-report";

    /** Setter-injected: the scheduler policy's per-job switch, absent in the unit test. */
    private com.certmanagement.service.scheduler.SchedulerExecutionPolicy executionPolicy;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setExecutionPolicy(com.certmanagement.service.scheduler.SchedulerExecutionPolicy executionPolicy) {
        this.executionPolicy = executionPolicy;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public TelemetryService(TelemetryProperties properties, InstallationIdentity installation,
                            ObjectProvider<BuildProperties> buildProperties, JdbcTemplate jdbc,
                            OrganizationRepository organizations, UserRepository users, UserMfaRepository userMfa,
                            CertificateRepository certificates, DiscoveredCertRepository discoveredCerts,
                            DomainCredentialConfigRepository credentialConfigs, Clock clock) {
        this(properties, installation, buildProperties, jdbc, organizations, users, userMfa, certificates,
                discoveredCerts, credentialConfigs, clock, RestClient.builder().build());
    }

    TelemetryService(TelemetryProperties properties, InstallationIdentity installation,
                     ObjectProvider<BuildProperties> buildProperties, JdbcTemplate jdbc,
                     OrganizationRepository organizations, UserRepository users, UserMfaRepository userMfa,
                     CertificateRepository certificates, DiscoveredCertRepository discoveredCerts,
                     DomainCredentialConfigRepository credentialConfigs, Clock clock, RestClient http) {
        this.properties = properties;
        this.installation = installation;
        this.buildProperties = buildProperties;
        this.jdbc = jdbc;
        this.organizations = organizations;
        this.users = users;
        this.userMfa = userMfa;
        this.certificates = certificates;
        this.discoveredCerts = discoveredCerts;
        this.credentialConfigs = credentialConfigs;
        this.clock = clock;
        this.http = http;
    }

    @PostConstruct
    void announce() {
        if (properties.isEnabled()) {
            log.info("Usage telemetry is ON: a report (docs/self-hosting.md#privacy-and-telemetry) goes to {} every {}",
                    properties.getEndpoint(), properties.getInterval());
        } else {
            log.info("Usage telemetry is off (CERTPING_TELEMETRY_ENABLED=false); nothing is sent");
        }
    }

    public boolean enabled() {
        return properties.isEnabled();
    }

    /** The report as it would be sent now. */
    public TelemetryReport preview() {
        Map<String, String> runtime = new LinkedHashMap<>();
        runtime.put("java", System.getProperty("java.version", "unknown"));
        runtime.put("os", System.getProperty("os.name", "unknown") + " " + System.getProperty("os.arch", ""));
        runtime.put("database", databaseVersion());

        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("organizations", quietly(organizations::count));
        counts.put("users", quietly(users::count));
        counts.put("usersWithMfa", quietly(userMfa::count));
        counts.put("certificates", quietly(certificates::count));
        counts.put("discoveredCertificates", quietly(discoveredCerts::count));
        counts.put("deploymentTargets", quietly(credentialConfigs::count));

        return new TelemetryReport(TelemetryReport.SCHEMA, installation.get().toString(),
                OffsetDateTime.now(clock).withOffsetSameInstant(ZoneOffset.UTC), version(), "open", runtime, counts);
    }

    @com.certmanagement.service.scheduler.RegisteredJob(JOB)
    @Scheduled(fixedDelayString = "${certping.telemetry.interval:PT24H}",
               initialDelayString = "${certping.telemetry.initial-delay:PT60M}")
    public void sendScheduled() {
        if (!properties.isEnabled() || (executionPolicy != null && !executionPolicy.canRun(JOB))) {
            return;
        }
        send();
    }

    /** Posts one report; true when the endpoint accepted it. */
    public boolean send() {
        TelemetryReport report;
        try {
            report = preview();
        } catch (RuntimeException e) {
            log.debug("Telemetry report not built: {}", e.toString());
            return false;
        }
        try {
            http.post().uri(properties.getEndpoint())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(report)
                    .retrieve()
                    .toBodilessEntity();
            log.debug("Telemetry report sent to {}", properties.getEndpoint());
            return true;
        } catch (RuntimeException e) {
            log.debug("Telemetry report not sent to {}: {}", properties.getEndpoint(), e.toString());
            return false;
        }
    }

    private String version() {
        BuildProperties build = buildProperties.getIfAvailable();
        return build == null || build.getVersion() == null ? "unknown" : build.getVersion();
    }

    private String databaseVersion() {
        try {
            return jdbc.execute((java.sql.Connection c) -> c.getMetaData().getDatabaseProductName() + " "
                    + c.getMetaData().getDatabaseMajorVersion());
        } catch (RuntimeException e) {
            return "unknown";
        }
    }

    private static long quietly(LongSupplier count) {
        try {
            return count.getAsLong();
        } catch (RuntimeException e) {
            return -1;
        }
    }
}
