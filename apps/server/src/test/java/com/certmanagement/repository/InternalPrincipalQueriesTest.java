// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/** The live-organization check the feature impact preview uses, run as SQL. */
@DataJpaTest(properties = "spring.jpa.hibernate.ddl-auto=none")
@AutoConfigureTestDatabase(replace = Replace.ANY)
@TestPropertySource(properties =
        "spring.datasource.url=jdbc:h2:mem:internal_principal;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE")
class InternalPrincipalQueriesTest {

    @Autowired
    private OrganizationRepository organizations;

    @Autowired
    private UserRepository users;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void schema() {
        jdbc.execute("drop table if exists organizations");
        jdbc.execute("drop table if exists users");
        jdbc.execute("""
                create table organizations (
                    id bigint primary key, active boolean, org_type varchar(10), is_deleted boolean not null)""");
        jdbc.execute("""
                create table users (
                    id int primary key, email varchar(255), active boolean, is_deleted boolean not null)""");

        jdbc.update("insert into organizations values (1, true, 'B2B', false)");
        jdbc.update("insert into organizations values (2, false, 'B2B', false)");
        jdbc.update("insert into organizations values (3, true, 'B2B', true)");
        jdbc.update("insert into organizations values (5, true, 'B2B', false)");
        jdbc.update("insert into users values (7, 'ada@example.com', false, false)");
        jdbc.update("insert into users values (8, 'gone@example.com', true, true)");
    }

    @Test
    void aDeletedOrganizationOrUser_isNotFound() {
        assertThat(organizations.existsLiveById(3L)).isFalse();
        assertThat(organizations.existsLiveById(2L)).isTrue();
    }
}
