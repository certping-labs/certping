// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class SmallstepTokenFactoryTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void revocationTokenBindsTheDecimalSerialAndRevokeAudience() throws Exception {
        String jwk = new ECKeyGenerator(Curve.P_256).keyID("provisioner-key").generate()
                .toJSONString();
        SmallstepCredentials credentials = new SmallstepCredentials(
                "https://step.internal", "Device CA", "certping-agent", jwk, "unused");

        SignedJWT token = SignedJWT.parse(
                SmallstepTokenFactory.createRevocation(credentials, "2748", CLOCK));

        assertThat(token.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(token.getHeader().getKeyID()).isEqualTo("provisioner-key");
        assertThat(token.getJWTClaimsSet().getSubject()).isEqualTo("2748");
        assertThat(token.getJWTClaimsSet().getAudience())
                .containsExactly("https://step.internal/1.0/revoke");
        assertThat(token.getJWTClaimsSet().getIssuer()).isEqualTo("certping-agent");
        assertThat(token.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(
                com.nimbusds.jose.jwk.ECKey.parse(jwk).toECPublicKey()))).isTrue();
    }
}
