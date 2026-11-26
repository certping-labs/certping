// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.DiscoveredCertEntity;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.OffsetDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The provider_data jsonb column holds a Jackson 3 JsonNode. Hibernate must use its Jackson 3 format
 * mapper, or saving and loading a Kubernetes discovery result fails ("Could not deserialize string").
 */
@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = {"spring.jpa.hibernate.ddl-auto=none", "spring.flyway.enabled=false"})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class DiscoveredCertJsonPostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @BeforeAll
    static void migrate() {
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration").load().migrate();
    }

    @Autowired private DiscoveredCertRepository repository;
    @Autowired private JdbcTemplate jdbc;

    private final ObjectMapper objectMapper = JsonMapper.builder().build();

    @Test
    void savesAndLoadsKubernetesProviderData() throws Exception {
        Long orgId = jdbc.queryForObject("""
                INSERT INTO organizations (name, domain, slug, org_type, is_deleted)
                VALUES ('Org ' || md5(random()::text), md5(random()::text) || '.test',
                        'org-' || md5(random()::text), 'B2B', false)
                RETURNING id
                """, Long.class);
        OffsetDateTime now = OffsetDateTime.now();
        DiscoveredCertEntity saved = repository.save(DiscoveredCertEntity.builder()
                .organizationId(orgId)
                .requestId("req-1")
                .targetType("KUBERNETES_SECRETS")
                .resourceId("lab/lab/app-tls")
                .providerData(objectMapper.readTree("{\"clusterName\":\"lab\",\"namespace\":\"lab\"}"))
                .discoveredAt(now)
                .createdAt(now)
                .updatedAt(now)
                .build());

        DiscoveredCertEntity loaded = repository.findById(saved.getId()).orElseThrow();
        assertThat(loaded.getProviderData().path("clusterName").asString()).isEqualTo("lab");

        loaded.setProviderData(objectMapper.readTree("{\"clusterName\":\"lab2\"}"));
        repository.save(loaded);
        assertThat(repository.findById(saved.getId()).orElseThrow()
                .getProviderData().path("clusterName").asString()).isEqualTo("lab2");
    }
}
