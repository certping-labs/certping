// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.health;

import com.certping.notification.transport.InboundConsumer;
import com.certping.notification.config.NotificationConsumers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.health.autoconfigure.application.AvailabilityHealthContributorAutoConfiguration;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.AvailabilityProbesAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.endpoint.EndpointAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointAutoConfiguration;
import org.springframework.boot.health.autoconfigure.contributor.HealthContributorAutoConfiguration;
import org.springframework.boot.health.autoconfigure.registry.HealthContributorRegistryAutoConfiguration;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.HealthEndpointAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.health.DataSourceHealthContributorAutoConfiguration;
import org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextAutoConfiguration;
import org.springframework.boot.servlet.autoconfigure.actuate.web.ServletManagementContextAutoConfiguration;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.availability.ApplicationAvailabilityAutoConfiguration;
import org.springframework.boot.http.converter.autoconfigure.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.DispatcherServletAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Loads the real application.yaml management settings over the actuator auto-configuration. */
@SpringBootTest(classes = StatusHealthGroupTest.Actuator.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class StatusHealthGroupTest {

    private static final String INTERNAL_ERROR = "jdbc:postgresql://internal-db-host:5432/certmanagerdb refused";

    @SpringBootConfiguration
    @ImportAutoConfiguration({
            JacksonAutoConfiguration.class,
            HttpMessageConvertersAutoConfiguration.class,
            DispatcherServletAutoConfiguration.class,
            WebMvcAutoConfiguration.class,
            ApplicationAvailabilityAutoConfiguration.class,
            EndpointAutoConfiguration.class,
            WebEndpointAutoConfiguration.class,
            HealthContributorAutoConfiguration.class,
            HealthContributorRegistryAutoConfiguration.class,
            HealthEndpointAutoConfiguration.class,
            AvailabilityHealthContributorAutoConfiguration.class,
            AvailabilityProbesAutoConfiguration.class,
            DataSourceHealthContributorAutoConfiguration.class,
            ManagementContextAutoConfiguration.class,
            ServletManagementContextAutoConfiguration.class})
    @Import(NotificationConsumerHealthIndicator.class)
    static class Actuator {

        @Bean
        DataSource dataSource() {
            return mock(DataSource.class);
        }

        @Bean
        InboundConsumer processor() {
            return mock(InboundConsumer.class);
        }

        @Bean
        NotificationConsumers notificationConsumers(InboundConsumer processor) {
            return new NotificationConsumers(List.of(processor));
        }
    }

    @Autowired private MockMvc mvc;
    @Autowired private DataSource dataSource;
    @Autowired private InboundConsumer processor;
    @Autowired private HealthEndpointGroups groups;

    @BeforeEach
    void resetDependencies() {
        reset(dataSource, processor);
    }

    @Test
    void statusIsUpWithOnlyTheStatusWhenDatabaseAndConsumersAreUp() throws Exception {
        databaseAnswers();
        when(processor.isRunning()).thenReturn(true);

        mvc.perform(get("/actuator/health/status"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"status\":\"UP\"}", true));
    }

    @Test
    void statusIsDownWhenTheConsumerStopped() throws Exception {
        databaseAnswers();
        when(processor.isRunning()).thenReturn(false);

        mvc.perform(get("/actuator/health/status"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().json("{\"status\":\"DOWN\"}", true));
    }

    @Test
    void statusIsDownWithoutTheErrorWhenTheDatabaseFails() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException(INTERNAL_ERROR));
        when(processor.isRunning()).thenReturn(true);

        String body = mvc.perform(get("/actuator/health/status"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().json("{\"status\":\"DOWN\"}", true))
                .andReturn().getResponse().getContentAsString();

        assertThat(body).doesNotContain("internal-db-host").doesNotContain("db");
    }

    @Test
    void readinessFollowsTheDatabaseAndIgnoresTheConsumer() throws Exception {
        databaseAnswers();
        when(processor.isRunning()).thenReturn(false);

        mvc.perform(get("/actuator/health/readiness")).andExpect(status().isOk());

        when(dataSource.getConnection()).thenThrow(new SQLException(INTERNAL_ERROR));

        mvc.perform(get("/actuator/health/readiness")).andExpect(status().isServiceUnavailable());
    }

    @Test
    void livenessIgnoresTheConsumerAndTheDatabase() throws Exception {
        when(dataSource.getConnection()).thenThrow(new SQLException(INTERNAL_ERROR));
        when(processor.isRunning()).thenReturn(false);

        mvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());
    }

    @Test
    void consumerBelongsOnlyToTheStatusGroup() {
        assertThat(groups.get("status").isMember("notificationConsumer")).isTrue();
        assertThat(groups.get("status").isMember("db")).isTrue();
        assertThat(groups.get("readiness").isMember("db")).isTrue();
        assertThat(groups.get("readiness").isMember("readinessState")).isTrue();
        assertThat(groups.get("readiness").isMember("notificationConsumer")).isFalse();
        assertThat(groups.get("liveness").isMember("notificationConsumer")).isFalse();
        assertThat(groups.get("liveness").isMember("db")).isFalse();
    }

    private void databaseAnswers() throws SQLException {
        Connection connection = mock(Connection.class);
        DatabaseMetaData metaData = mock(DatabaseMetaData.class);
        when(metaData.getDatabaseProductName()).thenReturn("PostgreSQL");
        when(connection.getMetaData()).thenReturn(metaData);
        when(connection.isValid(anyInt())).thenReturn(true);
        when(dataSource.getConnection()).thenReturn(connection);
    }
}
