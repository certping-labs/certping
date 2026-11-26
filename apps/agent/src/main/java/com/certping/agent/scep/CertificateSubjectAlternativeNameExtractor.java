// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.model.message.CertificateSubjectAlternativeName;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** Converts X.509 SANs to stable structured values for certificate inventory metadata. */
final class CertificateSubjectAlternativeNameExtractor {

    private CertificateSubjectAlternativeNameExtractor() {
    }

    static List<CertificateSubjectAlternativeName> extract(X509Certificate certificate) {
        if (certificate == null) {
            return List.of();
        }
        try {
            Extension extension = new JcaX509CertificateHolder(certificate)
                    .getExtension(Extension.subjectAlternativeName);
            if (extension == null) {
                return List.of();
            }
            List<CertificateSubjectAlternativeName> names = new ArrayList<>();
            for (GeneralName generalName : GeneralNames.getInstance(extension.getParsedValue()).getNames()) {
                try {
                    names.add(extract(generalName));
                } catch (Exception ignored) {
                    // One malformed SAN must not discard other valid inventory metadata.
                }
            }
            return List.copyOf(names);
        } catch (Exception exception) {
            return List.of();
        }
    }

    static String typeName(int tag) {
        return switch (tag) {
            case GeneralName.otherName -> "otherName";
            case GeneralName.rfc822Name -> "rfc822Name";
            case GeneralName.dNSName -> "dNSName";
            case GeneralName.x400Address -> "x400Address";
            case GeneralName.directoryName -> "directoryName";
            case GeneralName.ediPartyName -> "ediPartyName";
            case GeneralName.uniformResourceIdentifier -> "uniformResourceIdentifier";
            case GeneralName.iPAddress -> "iPAddress";
            case GeneralName.registeredID -> "registeredID";
            default -> "type" + tag;
        };
    }

    private static CertificateSubjectAlternativeName extract(GeneralName generalName) throws Exception {
        return switch (generalName.getTagNo()) {
            case GeneralName.otherName -> otherName(OtherName.getInstance(generalName.getName()));
            case GeneralName.rfc822Name, GeneralName.dNSName, GeneralName.uniformResourceIdentifier ->
                    value(generalName, DERIA5String.getInstance(generalName.getName()).getString());
            case GeneralName.directoryName ->
                    value(generalName, X500Name.getInstance(generalName.getName()).toString());
            case GeneralName.iPAddress -> value(generalName, InetAddress.getByAddress(
                    ASN1OctetString.getInstance(generalName.getName()).getOctets()).getHostAddress());
            case GeneralName.registeredID -> value(generalName,
                    ASN1ObjectIdentifier.getInstance(generalName.getName()).getId());
            default -> value(generalName, Base64.getEncoder().encodeToString(
                    generalName.getName().toASN1Primitive().getEncoded(ASN1Encoding.DER)));
        };
    }

    private static CertificateSubjectAlternativeName otherName(OtherName otherName) throws Exception {
        String value = otherName.getValue() instanceof ASN1String text
                ? text.getString()
                : Base64.getEncoder().encodeToString(
                        otherName.getValue().toASN1Primitive().getEncoded(ASN1Encoding.DER));
        return new CertificateSubjectAlternativeName(
                "otherName", otherName.getTypeID().getId(), value);
    }

    private static CertificateSubjectAlternativeName value(GeneralName generalName, String value) {
        return new CertificateSubjectAlternativeName(typeName(generalName.getTagNo()), null, value);
    }
}
