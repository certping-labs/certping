// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.model.enums.CertType;

import java.time.OffsetDateTime;

/**
 * Returned by all CA-specific issuance services (LE, DigiCert, GlobalSign).
 * Contains everything needed to build CERT_ISSUANCE_RESPONSE.
 *
 * @param orderId CA order identifier when applicable (e.g. DigiCert); null for Let's Encrypt
 * @param caOrderCost what the CA reported it charged for the order; null when it reported none
 * @param caOrderAction whether the certificate came from a new order or a free replacement; null when the CA
 *                      does not say
 */
public record IssuanceResult(
        String certSecretHandle,
        /** Versioned KV URI returned by Key Vault on write; null if not available. */
        String certSecretHandleWithVersion,
        String acmeAccountHandle,   // null for DigiCert
        String serial,
        String fingerprint,
        OffsetDateTime validFrom,
        OffsetDateTime validTo,
        String issuer,
        String orderId,
        String signatureAlgorithm,
        String signatureAlgorithmOid,
        String subjectDn,
        String commonName,
        String publicKeyAlgorithm,
        Integer keySize,
        String publicKeyCurve,
        String keyUsage,
        String extendedKeyUsage,
        String subjectKeyIdentifier,
        String authorityKeyIdentifier,
        CertType certType,
        CaOrderCost caOrderCost,
        CaOrderAction caOrderAction,
        KeyCustody keyCustody
) {

    public IssuanceResult(
            String certSecretHandle,
            String certSecretHandleWithVersion,
            String acmeAccountHandle,
            String serial,
            String fingerprint,
            OffsetDateTime validFrom,
            OffsetDateTime validTo,
            String issuer,
            String orderId,
            String signatureAlgorithm,
            String signatureAlgorithmOid,
            String subjectDn,
            String commonName,
            String publicKeyAlgorithm,
            Integer keySize,
            String publicKeyCurve,
            String keyUsage,
            String extendedKeyUsage,
            String subjectKeyIdentifier,
            String authorityKeyIdentifier,
            CertType certType,
            CaOrderCost caOrderCost,
            CaOrderAction caOrderAction) {
        this(certSecretHandle, certSecretHandleWithVersion, acmeAccountHandle, serial, fingerprint,
                validFrom, validTo, issuer, orderId, signatureAlgorithm, signatureAlgorithmOid,
                subjectDn, commonName, publicKeyAlgorithm, keySize, publicKeyCurve, keyUsage,
                extendedKeyUsage, subjectKeyIdentifier, authorityKeyIdentifier, certType, caOrderCost, caOrderAction,
                KeyCustody.PLATFORM_HELD);
    }

    public IssuanceResult withKeyCustody(KeyCustody custody) {
        return new IssuanceResult(certSecretHandle, certSecretHandleWithVersion, acmeAccountHandle, serial, fingerprint,
                validFrom, validTo, issuer, orderId, signatureAlgorithm, signatureAlgorithmOid,
                subjectDn, commonName, publicKeyAlgorithm, keySize, publicKeyCurve, keyUsage,
                extendedKeyUsage, subjectKeyIdentifier, authorityKeyIdentifier, certType, caOrderCost, caOrderAction,
                custody);
    }

    /** A result without a reported order cost. */
    public IssuanceResult(
            String certSecretHandle,
            String certSecretHandleWithVersion,
            String acmeAccountHandle,
            String serial,
            String fingerprint,
            OffsetDateTime validFrom,
            OffsetDateTime validTo,
            String issuer,
            String orderId,
            String signatureAlgorithm,
            String signatureAlgorithmOid,
            String subjectDn,
            String commonName,
            String publicKeyAlgorithm,
            Integer keySize,
            String publicKeyCurve,
            String keyUsage,
            String extendedKeyUsage,
            String subjectKeyIdentifier,
            String authorityKeyIdentifier,
            CertType certType) {
        this(certSecretHandle, certSecretHandleWithVersion, acmeAccountHandle, serial, fingerprint,
                validFrom, validTo, issuer, orderId, signatureAlgorithm, signatureAlgorithmOid,
                subjectDn, commonName, publicKeyAlgorithm, keySize, publicKeyCurve, keyUsage,
                extendedKeyUsage, subjectKeyIdentifier, authorityKeyIdentifier, certType, null, null,
                KeyCustody.PLATFORM_HELD);
    }

    /** The reported order amount, or null. */
    public String caOrderCostAmount() {
        return caOrderCost == null ? null : caOrderCost.amount();
    }

    /** The reported order currency, or null. */
    public String caOrderCostCurrency() {
        return caOrderCost == null ? null : caOrderCost.currency();
    }
}
