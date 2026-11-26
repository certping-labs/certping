// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * SCEP (RFC 8894) attribute OIDs and enum values. The attribute OIDs live under the historical
 * Verisign arc {@code 2.16.840.1.113733.1.9.x}; see RFC 8894 section 3.2.1.
 */
public final class ScepConstants {

    private ScepConstants() {
    }

    private static final String P = "2.16.840.1.113733.1.9.";

    public static final ASN1ObjectIdentifier MESSAGE_TYPE    = new ASN1ObjectIdentifier(P + "2");
    public static final ASN1ObjectIdentifier PKI_STATUS      = new ASN1ObjectIdentifier(P + "3");
    public static final ASN1ObjectIdentifier FAIL_INFO       = new ASN1ObjectIdentifier(P + "4");
    public static final ASN1ObjectIdentifier SENDER_NONCE    = new ASN1ObjectIdentifier(P + "5");
    public static final ASN1ObjectIdentifier RECIPIENT_NONCE = new ASN1ObjectIdentifier(P + "6");
    public static final ASN1ObjectIdentifier TRANSACTION_ID  = new ASN1ObjectIdentifier(P + "7");

    // messageType attribute values
    public static final int MSG_CERT_REP    = 3;
    public static final int MSG_RENEWAL_REQ = 17;
    public static final int MSG_PKCS_REQ    = 19;
    public static final int MSG_CERT_POLL   = 20;
    public static final int MSG_GET_CERT    = 21;
    public static final int MSG_GET_CRL     = 22;

    // pkiStatus values
    public static final int PKI_STATUS_SUCCESS = 0;
    public static final int PKI_STATUS_FAILURE = 2;
    public static final int PKI_STATUS_PENDING = 3;

    // failInfo values
    public static final int FAIL_BAD_ALG           = 0;
    public static final int FAIL_BAD_MESSAGE_CHECK = 1;
    public static final int FAIL_BAD_REQUEST       = 2;
    public static final int FAIL_BAD_TIME          = 3;
    public static final int FAIL_BAD_CERT_ID       = 4;

    // response content types
    public static final String CT_PKI_MESSAGE = "application/x-pki-message";
    public static final String CT_CA_CERT     = "application/x-x509-ca-cert";
    public static final String CT_CA_RA_CERT  = "application/x-x509-ca-ra-cert";
    public static final String CT_NEXT_CA     = "application/x-x509-next-ca-cert";
}
