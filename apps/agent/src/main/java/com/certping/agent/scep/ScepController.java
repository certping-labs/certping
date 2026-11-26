// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;

/**
 * The SCEP device-facing surface (RFC 8894). One route carries all four URL operations via
 * {@code ?operation=}; transactional message types ride inside {@code PKIOperation}. Every response is
 * {@code Cache-Control: no-store}. Transport errors are HTTP 4xx/5xx; SCEP outcomes ride inside a
 * signed CertRep at HTTP 200.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
// Windows/NDES and other SCEP clients hard-append "/pkiclient.exe" to the configured SCEP URL (the
// classic cgi-bin SCEP convention), so the endpoint must answer at both the bare path and that suffix.
@RequestMapping({"/scep/v1/{endpointId}", "/scep/v1/{endpointId}/pkiclient.exe"})
@ConditionalOnProperty(prefix = "agent.scep", name = "enabled", havingValue = "true")
public class ScepController {

    private final ScepService scep;

    @GetMapping(params = "operation=GetCACaps")
    ResponseEntity<byte[]> caps(@PathVariable String endpointId) {
        BinaryResponse r = scep.getCaCaps(endpointId);
        return binary(r.contentType(), r.body());
    }

    @GetMapping(params = "operation=GetCACert")
    ResponseEntity<byte[]> caCert(@PathVariable String endpointId) {
        BinaryResponse r = scep.getCaCert(endpointId);
        return binary(r.contentType(), r.body());
    }

    @GetMapping(params = "operation=GetNextCACert")
    ResponseEntity<byte[]> nextCaCert(@PathVariable String endpointId) {
        return scep.supportsRollover(endpointId)
                ? binary(ScepConstants.CT_NEXT_CA, scep.getNextCaCert(endpointId))
                : ResponseEntity.badRequest().build();
    }

    // RFC 8894 does not require a Content-Type and clients such as sscep send none, so read the raw body.
    @PostMapping(params = "operation=PKIOperation")
    ResponseEntity<byte[]> pkiPost(@PathVariable String endpointId, @RequestBody byte[] body) {
        BinaryResponse r = scep.pkiOperation(endpointId, body);
        return binary(r.contentType(), r.body());
    }

    @GetMapping(params = "operation=PKIOperation")
    ResponseEntity<byte[]> pkiGet(@PathVariable String endpointId, @RequestParam String message) {
        return pkiPost(endpointId, Base64.getMimeDecoder().decode(message));
    }

    @GetMapping
    ResponseEntity<byte[]> unknownOperation() {
        return ResponseEntity.badRequest().build();
    }

    private static ResponseEntity<byte[]> binary(String contentType, byte[] body) {
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .cacheControl(CacheControl.noStore())
                .body(body);
    }
}
