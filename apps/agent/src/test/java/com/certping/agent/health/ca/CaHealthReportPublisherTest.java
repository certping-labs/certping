// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.health.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.CaConnectorHealth;
import com.certping.agent.model.message.CaHealthReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@DisplayName("CaHealthReportPublisher")
class CaHealthReportPublisherTest {

    private AgentProperties properties;
    private AgentMessageSender sender;

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.setOrganizationId("org-42");
        sender = mock(AgentMessageSender.class);
    }

    @Test
    @DisplayName("aggregates every configured connector into one report")
    void aggregatesAllProbes() {
        CaHealthReport report = publisher(probe("EJBCA"), probe("DIGICERT")).buildReport();

        assertThat(report.getReportVersion()).isEqualTo(1);
        assertThat(report.getOrganizationId()).isEqualTo("org-42");
        assertThat(report.getRespondedAt()).isNotBlank();
        assertThat(report.getConnectors()).extracting(CaConnectorHealth::getCaProvider)
                .containsExactly("EJBCA", "DIGICERT");
    }

    @Test
    @DisplayName("a probe that throws costs its own connector, not the whole report")
    void oneThrowingProbeDoesNotLoseTheOthers() {
        CaHealthProbe exploding = mock(CaHealthProbe.class);
        org.mockito.Mockito.when(exploding.caProvider()).thenReturn("BROKEN");
        org.mockito.Mockito.when(exploding.probe()).thenThrow(new IllegalStateException("boom"));

        CaHealthReport report = publisher(exploding, probe("EJBCA")).buildReport();

        assertThat(report.getConnectors()).extracting(CaConnectorHealth::getCaProvider)
                .containsExactly("EJBCA");
    }

    @Test
    @DisplayName("a probe returning null is skipped rather than serialized as a null connector")
    void nullProbeResultIsSkipped() {
        CaHealthProbe nullProbe = mock(CaHealthProbe.class);
        org.mockito.Mockito.when(nullProbe.probe()).thenReturn(null);

        assertThat(publisher(nullProbe).buildReport().getConnectors()).isEmpty();
    }

    @Test
    @DisplayName("publishes when there is something to say")
    void publishesReport() {
        publisher(probe("EJBCA")).publishCaHealthReport();

        verify(sender).sendCaHealthReport(any(CaHealthReport.class));
    }

    @Test
    @DisplayName("stays silent when no CA connector is registered")
    void noConnectorsMeansNoMessage() {
        publisher().publishCaHealthReport();

        verify(sender, never()).sendCaHealthReport(any());
    }

    @Test
    @DisplayName("a failed send must not kill the scheduler thread")
    void sendFailureIsContained() {
        doThrow(new RuntimeException("server down"))
                .when(sender).sendCaHealthReport(any(CaHealthReport.class));

        // Escaping here would terminate the fixedDelay schedule and stop all future reports.
        assertThatCode(() -> publisher(probe("EJBCA")).publishCaHealthReport())
                .doesNotThrowAnyException();
    }

    private CaHealthReportPublisher publisher(CaHealthProbe... probes) {
        return new CaHealthReportPublisher(properties, sender, List.of(probes));
    }

    private CaHealthProbe probe(String provider) {
        CaHealthProbe probe = mock(CaHealthProbe.class);
        org.mockito.Mockito.when(probe.caProvider()).thenReturn(provider);
        org.mockito.Mockito.when(probe.probe())
                .thenReturn(CaConnectorHealth.builder().caProvider(provider).build());
        return probe;
    }
}
