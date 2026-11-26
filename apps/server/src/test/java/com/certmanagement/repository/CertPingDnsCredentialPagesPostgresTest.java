// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import com.certmanagement.entity.CredentialReferenceEntity;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers(disabledWithoutDocker = true)
@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class CertPingDnsCredentialPagesPostgresTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired private CredentialReferenceRepository credentials;
    @Autowired private JdbcTemplate jdbc;

    private long org;

    @BeforeAll
    static void migrate() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration")
                .load()
                .migrate();
    }

    @BeforeEach
    void organization() {
        jdbc.update("DELETE FROM credential_references");
        org = jdbc.queryForObject("""
                INSERT INTO organizations (name, domain, slug, org_type, is_deleted)
                VALUES ('Org ' || md5(random()::text), md5(random()::text) || '.test',
                        'org-' || md5(random()::text), 'B2B', false)
                RETURNING id
                """, Long.class);
    }

    @Test
    void onlyActiveCertPingDnsCredentialsAreRead() {
        insert("certping", "CERTPING", "DNS", "ACTIVE", false);
        insert("deleted", "CERTPING", "DNS", "ACTIVE", true);
        insert("inactive", "CERTPING", "DNS", "DELETED", false);
        insert("third-party", "CLOUDFLARE", "DNS", "ACTIVE", false);
        insert("not-dns", "CERTPING", "DEPLOYMENT", "ACTIVE", false);

        assertThat(page(0L, 50)).extracting(CredentialReferenceEntity::getCredentialXref).containsExactly("certping");
    }

    @Test
    void pagesFollowTheIdAfterTheLastOneRead() {
        for (int i = 0; i < 5; i++) {
            insert("key-" + i, "CERTPING", "DNS", "ACTIVE", false);
        }

        List<CredentialReferenceEntity> first = page(0L, 3);
        List<CredentialReferenceEntity> second = page(first.get(first.size() - 1).getId(), 3);

        assertThat(first).extracting(CredentialReferenceEntity::getCredentialXref)
                .containsExactly("key-0", "key-1", "key-2");
        assertThat(second).extracting(CredentialReferenceEntity::getCredentialXref).containsExactly("key-3", "key-4");
    }

    private List<CredentialReferenceEntity> page(long afterId, int size) {
        return credentials.findByProviderAndTypeAndStatusAndIsDeletedFalseAndIdGreaterThanOrderByIdAsc(
                "CERTPING", "DNS", "ACTIVE", afterId, PageRequest.of(0, size));
    }

    private void insert(String xref, String provider, String type, String status, boolean deleted) {
        jdbc.update("INSERT INTO credential_references (credential_xref, organization_id, provider, type, status,"
                + " secret_handle, is_deleted) VALUES (?, ?, ?, ?, ?, 'https://kv.test/secrets/x', ?)",
                xref, org, provider, type, status, deleted);
    }
}
