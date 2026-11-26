// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class FlywayMigrationVersionUniquenessTest {
    private static final Pattern VERSIONED_MIGRATION = Pattern.compile("^V(.+?)__.+\\.sql$");

    @Test
    void versionedMigrationsHaveUniqueFlywayVersions() throws IOException {
        Resource[] migrations = new PathMatchingResourcePatternResolver()
                .getResources("classpath*:db/migration/V*__*.sql");

        Map<MigrationVersion, List<String>> migrationsByVersion = Arrays.stream(migrations)
                .map(Resource::getFilename)
                .filter(filename -> filename != null && VERSIONED_MIGRATION.matcher(filename).matches())
                .collect(Collectors.groupingBy(
                        FlywayMigrationVersionUniquenessTest::migrationVersion,
                        TreeMap::new,
                        Collectors.toList()));

        assertThat(migrationsByVersion).allSatisfy((version, filenames) ->
                assertThat(filenames)
                        .as("Files using Flyway version %s", version)
                        .hasSize(1));
    }

    private static MigrationVersion migrationVersion(String filename) {
        Matcher matcher = VERSIONED_MIGRATION.matcher(filename);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Not a versioned Flyway migration: " + filename);
        }
        return MigrationVersion.fromVersion(matcher.group(1).replace('_', '.'));
    }
}
