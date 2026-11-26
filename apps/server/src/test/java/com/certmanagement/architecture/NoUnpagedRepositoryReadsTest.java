// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.architecture;

import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Loading an organisation's whole certificate set into memory once took a production server down.
 * Request paths must page, stream or aggregate; this fails the build if an unpaged read comes back.
 */
class NoUnpagedRepositoryReadsTest {

    private static final Path MAIN_SOURCES = Path.of("src/main/java");
    private static final String UNPAGED = "Pageable.unpaged()";

    /** The repositories on the certificate read path. */
    private static final List<Class<?>> CERTIFICATE_READ_PATH =
            List.of(CertificateRepository.class, UserDomainCertRepository.class);

    /** Every collection finder on the read path, and what bounds it. */
    private static final Map<String, String> BOUNDED_BY_DESIGN = Map.of(
            "findByOrganizationIdAndCertificateXrefIn", "xrefs from one page of deployments",
            "findActiveByUserDomainCertIdAndOrganizationId", "one domain's live certificates",
            "countByStatusForOrganization", "one row per status",
            "countPqcAlgorithmsByOrganizationId", "one row per algorithm, key size, curve and usage",
            "findDistinctCertSecretHandlesByOrganizationId", "agent deep health check needs every path",
            "findDistinctAcmeAccountHandlesByOrganizationId", "agent deep health check needs every path",
            "findDistinctCaCredentialHandlesByOrganizationId", "agent deep health check needs every path",
            "findActiveWithKvPathByOrganizationId", "organization deletion deletes every secret");

    @Test
    void mainSourcesNeverRequestAnUnpagedResult() throws IOException {
        List<String> offenders;
        try (Stream<Path> files = Files.walk(MAIN_SOURCES)) {
            offenders = files
                    .filter(path -> path.toString().endsWith(".java"))
                    .filter(this::containsUnpaged)
                    .map(MAIN_SOURCES::relativize)
                    .map(Path::toString)
                    .sorted()
                    .toList();
        }

        assertThat(offenders)
                .as("files calling %s; page, stream or aggregate instead", UNPAGED)
                .isEmpty();
    }

    /**
     * A finder on the certificate read path that returns a collection must be listed in
     * {@link #BOUNDED_BY_DESIGN} with what bounds it. A collection argument is not enough: a list
     * of statuses bounds nothing. Anything else pages, slices, streams or returns one row.
     */
    @Test
    void certificateReadPathReturnsNoUnboundedList() {
        List<String> offenders = CERTIFICATE_READ_PATH.stream()
                .flatMap(repository -> Arrays.stream(repository.getDeclaredMethods()))
                .filter(method -> Collection.class.isAssignableFrom(method.getReturnType()))
                .filter(method -> !BOUNDED_BY_DESIGN.containsKey(method.getName()))
                .map(method -> method.getDeclaringClass().getSimpleName() + "." + method.getName())
                .sorted()
                .toList();

        assertThat(offenders)
                .as("unbounded collection finders; page, stream or aggregate, or list what bounds them")
                .isEmpty();
    }

    @Test
    void everyBoundedByDesignEntryStillExists() {
        List<String> declared = CERTIFICATE_READ_PATH.stream()
                .flatMap(repository -> Arrays.stream(repository.getDeclaredMethods()))
                .map(Method::getName)
                .toList();

        assertThat(declared).containsAll(BOUNDED_BY_DESIGN.keySet());
    }

    private boolean containsUnpaged(Path file) {
        try {
            return Files.readString(file).contains(UNPAGED);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + file, e);
        }
    }
}
