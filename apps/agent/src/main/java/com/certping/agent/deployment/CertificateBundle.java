// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment;

/**
 * Parsed certificate bundle extracted from the PEM string the issuance services store in the secret store.
 *
 * Bundle format written by LetsEncryptAcmeService / DigiCertIssuanceService:
 *   [leaf cert PEM]
 *   [intermediate cert(s) PEM]
 *   [root cert PEM]
 *   [private key PEM]
 *
 * Usage per target:
 *   Azure KV import → PKCS8(privateKey) + "\n" + fullChain  (key first, then certs)
 *   AWS ACM import  → leafCertificate, privateKey, certChain (intermediates only, no leaf)
 */
public record CertificateBundle(
        /** PEM private key block — may be PKCS#1 or PKCS#8. */
        String privateKey,

        /** PEM of the leaf (end-entity) certificate — first cert block in the bundle. */
        String leafCertificate,

        /**
         * PEM of intermediate + root certificates only — without the leaf.
         * AWS ACM requires the chain field to NOT include the leaf certificate.
         */
        String certChain,

        /** Full chain PEM including leaf — all cert blocks concatenated. Used for Azure KV import. */
        String fullChain
) {}
