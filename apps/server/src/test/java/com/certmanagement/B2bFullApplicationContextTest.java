// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers(disabledWithoutDocker = true)
class B2bFullApplicationContextTest extends FullApplicationContextTest {

    @Container
    private static final PostgreSQLContainer POSTGRES = postgres();

    @Container
    private static final GenericContainer<?> REDIS = redis();

    @DynamicPropertySource
    static void stackProperties(DynamicPropertyRegistry registry) {
        registerStackProperties(registry, POSTGRES, REDIS);
        // The status page lists notifications only when mail is configured; nothing is sent here.
        registry.add("MAIL_HOST", () -> "127.0.0.1");
    }

    @Override
    protected String organizationType() {
        return "B2B";
    }
}
