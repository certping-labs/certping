// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps the transport-level SCEP failures to HTTP status. A <em>rejected request</em> (bad challenge,
 * CA refusal) never reaches here — it returns a signed {@code CertRep FAILURE} at HTTP 200 from the
 * service. Only requests that never reached a SCEP decision, and the retry conflict, surface as 4xx/5xx.
 * A transient Intune outage returns 503 so the client retries rather than treating it as a hard failure.
 */
@Slf4j
@RestControllerAdvice(assignableTypes = ScepController.class)
@ConditionalOnProperty(prefix = "agent.scep", name = "enabled", havingValue = "true")
public class ScepExceptionAdvice {

    @ExceptionHandler({
            UnknownEndpointException.class,
            BadPkiMessageException.class,
            IllegalArgumentException.class})
    ResponseEntity<Void> badRequest(Exception exception) {
        // The exception class, never its message: a parse failure comes out of the ASN.1 layer and
        // its text can echo the request. The class alone separates a bad signature from a bad
        // decrypt from an unknown route, which is what the operator needs.
        log.warn("SCEP request rejected before a SCEP decision (400): type={} cause={}",
                exception.getClass().getSimpleName(), causeType(exception));
        return ResponseEntity.badRequest().build();
    }

    @ExceptionHandler(ScepConflictException.class)
    ResponseEntity<Void> conflict() {
        log.warn("SCEP request rejected (409): the transaction id was replayed with a different CSR");
        return ResponseEntity.status(409).build();
    }

    @ExceptionHandler({IntuneUnavailableException.class, CaUnavailableException.class})
    ResponseEntity<Void> unavailable() {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .header(HttpHeaders.RETRY_AFTER, "30")
                .build();
    }

    @ExceptionHandler(IllegalStateException.class)
    ResponseEntity<Void> serverError(Exception exception) {
        log.error("SCEP request failed (500): type={} cause={}",
                exception.getClass().getSimpleName(), causeType(exception));
        return ResponseEntity.internalServerError().build();
    }

    /**
     * No line for the 503 handler on purpose. A platform outage makes a whole fleet retry on the
     * Retry-After cadence, and the underlying cause is already logged once where it happened.
     */
    private static String causeType(Exception exception) {
        return exception.getCause() == null ? null : exception.getCause().getClass().getSimpleName();
    }
}
