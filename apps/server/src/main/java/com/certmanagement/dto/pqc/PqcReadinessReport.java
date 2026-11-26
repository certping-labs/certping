// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.pqc;

import java.util.List;

/**
 * Response DTO for GET /api/v1/pqc-readiness.
 *
 * Summarises the quantum-readiness posture of an organisation's certificate
 * inventory using NIST IR 8547 (Nov 2024) terminology and deprecation timelines.
 * Per-certificate rows are served paged by GET /api/v1/pqc-readiness/certificates.
 */
public record PqcReadinessReport(Summary summary, List<AlgorithmGroup> algorithms) {

    /**
     * Organisation-level summary counts.
     *
     * @param total            total active certificates
     * @param pqcCompliant     certs using a NIST-approved PQC algorithm (FIPS 203/204/205)
     * @param deprecated2030   certs whose algorithm is deprecated by NIST after 2030
     * @param disallowed2035   certs whose algorithm is disallowed by NIST after 2035
     * @param unknown          certs with no algorithm data (issued before metadata collection)
     * @param highHndlRisk     certs used for key exchange — vulnerable to Harvest Now Decrypt Later attacks today
     */
    public record Summary(
            int total,
            int pqcCompliant,
            int deprecated2030,
            int disallowed2035,
            int unknown,
            int highHndlRisk
    ) {}

    /**
     * Certificates sharing one public key algorithm, key size and curve.
     *
     * @param publicKeyAlgorithm public key algorithm name (e.g. RSA, EC), null when not collected
     * @param keySize            public key size in bits
     * @param curve              EC curve name if applicable
     * @param quantumStatus      NIST-aligned quantum risk status of this algorithm
     * @param deprecationYear    year NIST deprecates this algorithm (null if PQC_COMPLIANT or UNKNOWN)
     * @param disallowedYear     year NIST disallows this algorithm (null if PQC_COMPLIANT or UNKNOWN)
     * @param certificates       number of active certificates in the group
     */
    public record AlgorithmGroup(
            String publicKeyAlgorithm,
            Integer keySize,
            String curve,
            QuantumStatus quantumStatus,
            Integer deprecationYear,
            Integer disallowedYear,
            long certificates
    ) {
        public AlgorithmGroup plus(long moreCertificates) {
            return new AlgorithmGroup(publicKeyAlgorithm, keySize, curve, quantumStatus,
                    deprecationYear, disallowedYear, certificates + moreCertificates);
        }
    }

    /**
     * Per-certificate PQC detail.
     *
     * @param certificateXref   unique cert identifier
     * @param commonName        certificate common name or domain
     * @param signatureAlgorithm full signature algorithm string (e.g. SHA256withRSA)
     * @param publicKeyAlgorithm public key algorithm name (e.g. RSA, EC), null when not collected
     * @param keySize           public key size in bits
     * @param curve             EC curve name if applicable
     * @param quantumStatus     NIST-aligned quantum risk status
     * @param hndlRisk          Harvest Now Decrypt Later risk — HIGH for key-exchange certs
     * @param deprecationYear   year NIST deprecates this algorithm (null if PQC_COMPLIANT or UNKNOWN)
     * @param disallowedYear    year NIST disallows this algorithm (null if PQC_COMPLIANT or UNKNOWN)
     * @param complianceRef     reference standard driving this classification
     * @param remediationAdvice actionable plain-English migration advice
     * @param source            MANAGED (issued through CertPing; certificateXref is its xref) or DISCOVERED
     *                          (found by discovery; certificateXref is the resource id where it was found)
     */
    public record CertDetail(
            String certificateXref,
            String commonName,
            String signatureAlgorithm,
            String publicKeyAlgorithm,
            Integer keySize,
            String curve,
            QuantumStatus quantumStatus,
            HndlRisk hndlRisk,
            Integer deprecationYear,
            Integer disallowedYear,
            String complianceRef,
            String remediationAdvice,
            String source
    ) {}

    /**
     * NIST IR 8547 (Nov 2024) aligned quantum risk status.
     *
     * <ul>
     *   <li>PQC_COMPLIANT    — uses a NIST-approved PQC algorithm (FIPS 203/204/205); safe against quantum.</li>
     *   <li>DEPRECATED_2030  — uses a quantum-vulnerable algorithm at the 112-bit security level (e.g. RSA-2048,
     *                          ECDSA P-224); NIST deprecates after 2030, disallows after 2035.</li>
     *   <li>DISALLOWED_2035  — uses a quantum-vulnerable algorithm at ≥128-bit classical security level (e.g.
     *                          RSA-3072, ECDSA P-256/P-384, EdDSA); NIST disallows after 2035.</li>
     *   <li>UNKNOWN          — algorithm data not yet collected; cert was issued before metadata extraction.</li>
     * </ul>
     *
     * Reference: NIST IR 8547 Tables 2 & 3 — https://csrc.nist.gov/pubs/ir/8547/ipd
     */
    public enum QuantumStatus {
        PQC_COMPLIANT,
        DEPRECATED_2030,
        DISALLOWED_2035,
        UNKNOWN
    }

    /**
     * Harvest Now Decrypt Later (HNDL) risk level.
     *
     * Certs used for key exchange protect data confidentiality and are vulnerable to
     * HNDL attacks TODAY — adversaries can collect encrypted traffic now and decrypt
     * it post-Q-Day. Signature-only certs are only broken when a quantum computer
     * actually exists, making them lower immediate priority.
     *
     * Derived from the keyUsage extension stored in certificate_crypto_metadata.
     *
     * Reference: CISA Quantum Readiness Factsheet (2023) — https://www.cisa.gov/sites/default/files/2023-08/Quantum%20Readiness_Final_CLEAR_508c%20%283%29.pdf
     * Reference: OMB M-23-02 Item 4 — service type must be recorded in cryptographic inventory
     */
    public enum HndlRisk {
        /** keyUsage includes keyEncipherment or keyAgreement — key exchange cert, high HNDL risk. */
        HIGH,
        /** keyUsage is digitalSignature / contentCommitment only — lower immediate priority. */
        LOW,
        /** keyUsage not available — cannot determine HNDL risk. */
        UNKNOWN
    }
}
