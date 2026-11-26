// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

/**
 * Shared PEM helpers for the Azure KV adapters. Extracts the PKCS#1 → PKCS#8 wrap that
 * was duplicated in {@code AzureDeploymentAdapter} and {@code AzureAppGatewayDeploymentAdapter}.
 */
@Slf4j
public final class AzurePemSupport {

    private AzurePemSupport() {}

    /** Returns a PKCS#8-encoded PEM private key (input may be PKCS#1 or already PKCS#8). */
    public static String toPkcs8(String keyPem) {
        if (keyPem == null) return null;
        if (keyPem.contains("-----BEGIN PRIVATE KEY-----")) {
            return keyPem;
        }
        if (keyPem.contains("-----BEGIN RSA PRIVATE KEY-----")) {
            try {
                String b64 = keyPem
                        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                        .replace("-----END RSA PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");
                byte[] pkcs1 = Base64.getDecoder().decode(b64);
                byte[] pkcs8 = wrapPkcs1InPkcs8(pkcs1);
                String pkcs8B64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(pkcs8);
                return "-----BEGIN PRIVATE KEY-----\n" + pkcs8B64 + "\n-----END PRIVATE KEY-----";
            } catch (Exception e) {
                log.warn("PKCS#1 → PKCS#8 conversion failed, using key as-is: {}", e.getMessage());
                return keyPem;
            }
        }
        return keyPem;
    }

    private static byte[] wrapPkcs1InPkcs8(byte[] pkcs1) {
        byte[] oid = {0x30, 0x0d,
                0x06, 0x09,
                0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
                0x05, 0x00};
        byte[] version = {0x02, 0x01, 0x00};
        byte[] octetHeader = derLength(0x04, pkcs1.length);
        int totalInner = version.length + oid.length + octetHeader.length + pkcs1.length;
        byte[] outerHeader = derLength(0x30, totalInner);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            bos.write(outerHeader);
            bos.write(version);
            bos.write(oid);
            bos.write(octetHeader);
            bos.write(pkcs1);
        } catch (IOException ignored) {}
        return bos.toByteArray();
    }

    private static byte[] derLength(int tag, int length) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(tag);
        if (length < 128) {
            bos.write(length);
        } else if (length < 256) {
            bos.write(0x81);
            bos.write(length);
        } else {
            bos.write(0x82);
            bos.write((length >> 8) & 0xff);
            bos.write(length & 0xff);
        }
        return bos.toByteArray();
    }
}
