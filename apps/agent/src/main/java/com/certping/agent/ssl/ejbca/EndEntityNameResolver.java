// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * Chooses the EJBCA end entity name for an enrolling device.
 *
 * <p>The end entity is the record a certificate hangs off in EJBCA, and its name is the key an
 * operator searches by. One entity per device keeps the audit trail per-device and stops
 * concurrent enrollments racing on a single shared record, so the name has to be stable for a
 * given device and distinct between devices.
 */
@Slf4j
@Component
public class EndEntityNameResolver {

    /** The CSR fields a name can be taken from, in fallback order. Mirrors Keyfactor's own
     *  cert-manager issuer; EJBCA's native SCEP RA mode likewise takes the CN. */
    public static final List<String> NAME_SOURCES = List.of("cn", "dns", "uri", "ip");

    /**
     * Defensive bound. MDM device ids can be long, and an over-long username is a pointless round
     * trip to the CA. Not measured against EJBCA's own limit — this only has to be conservative.
     */
    private static final int MAX_LENGTH = 250;

    /**
     * @param deviceId stable identifier for the enrolling device; when null the name is derived
     *                 from the CSR instead
     */
    public String resolve(String csrPem, String deviceId, AgentProperties.EjbcaProperties config) {
        String base = deviceId != null && !deviceId.isBlank()
                ? deviceId.trim()
                : deriveFromCsr(csrPem, config.getEndEntityNameSource());

        if (base == null || base.isBlank()) {
            throw new PermanentAgentException("EJBCA_END_ENTITY_NAME_UNRESOLVED",
                    "Could not determine an EJBCA end entity name: no device id was supplied and "
                            + "the CSR has no common name or usable SAN.");
        }

        String prefix = config.getEndEntityNamePrefix();
        String name = prefix != null && !prefix.isBlank() ? prefix.trim() + base : base;
        return requireWithinLengthLimit(name);
    }

    /**
     * A blank {@code source} walks {@link #NAME_SOURCES} in order; naming one restricts derivation
     * to that field, so the name cannot silently change shape when a CSR omits a component.
     */
    private String deriveFromCsr(String csrPem, String source) {
        String wanted = source == null ? "" : source.trim().toLowerCase(Locale.ROOT);
        if (!wanted.isEmpty() && !NAME_SOURCES.contains(wanted)) {
            throw new PermanentAgentException("EJBCA_CONFIG_INVALID",
                    "agent.ejbca.end-entity-name-source must be one of " + NAME_SOURCES
                            + " (got '" + source + "')");
        }

        PKCS10CertificationRequest csr = parseCsr(csrPem);
        for (String candidateSource : wanted.isEmpty() ? NAME_SOURCES : List.of(wanted)) {
            String candidate = switch (candidateSource) {
                case "cn" -> commonName(csr);
                case "dns" -> firstSan(csr, GeneralName.dNSName);
                case "uri" -> firstSan(csr, GeneralName.uniformResourceIdentifier);
                case "ip" -> firstSan(csr, GeneralName.iPAddress);
                default -> null;
            };
            if (candidate != null) {
                return candidate;
            }
        }
        return null;
    }

    private String requireWithinLengthLimit(String name) {
        if (name.length() <= MAX_LENGTH) {
            return name;
        }
        // Truncating would silently merge two devices sharing a long prefix onto one end entity,
        // resetting the first device's record and hanging both devices' certificates off it.
        // That is an identity collision, so fail loudly instead.
        throw new PermanentAgentException("EJBCA_END_ENTITY_NAME_TOO_LONG",
                "EJBCA end entity name is " + name.length() + " characters, over the " + MAX_LENGTH
                        + " limit. Shorten agent.ejbca.end-entity-name-prefix or supply a shorter "
                        + "device id — truncating would risk merging two devices onto one identity.");
    }

    private String commonName(PKCS10CertificationRequest csr) {
        RDN[] rdns = csr.getSubject().getRDNs(BCStyle.CN);
        if (rdns.length == 0) {
            return null;
        }
        String commonName = IETFUtils.valueToString(rdns[0].getFirst().getValue());
        return commonName == null || commonName.isBlank() ? null : commonName.trim();
    }

    private String firstSan(PKCS10CertificationRequest csr, int generalNameTag) {
        for (Attribute attribute : csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
            for (ASN1Encodable value : attribute.getAttributeValues()) {
                GeneralNames sans;
                try {
                    sans = GeneralNames.fromExtensions(
                            Extensions.getInstance(value), Extension.subjectAlternativeName);
                } catch (IllegalArgumentException e) {
                    // The CSR is attacker-supplied; a malformed extensionRequest is a bad request,
                    // not an internal error.
                    throw new PermanentAgentException("EJBCA_CSR_INVALID",
                            "CSR contains a malformed extensionRequest attribute: " + e.getMessage(), e);
                }
                if (sans == null) {
                    continue;
                }
                for (GeneralName name : sans.getNames()) {
                    if (name.getTagNo() == generalNameTag) {
                        String text = generalNameToText(name);
                        if (text != null && !text.isBlank()) {
                            return text.trim();
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * dNSName and URI are string types, but iPAddress wraps raw octets whose {@code toString()}
     * is a hex dump — {@code 10.42.0.7} renders as {@code #0a2a0007}, which would become an
     * unsearchable end entity name.
     */
    private String generalNameToText(GeneralName name) {
        if (name.getTagNo() != GeneralName.iPAddress) {
            return name.getName().toString();
        }
        try {
            byte[] octets = ASN1OctetString.getInstance(name.getName()).getOctets();
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (Exception e) {
            log.warn("Could not decode an IP SAN into an address, ignoring it: {}", e.getMessage());
            return null;
        }
    }

    private PKCS10CertificationRequest parseCsr(String csrPem) {
        try {
            String base64 = csrPem
                    .replaceAll("-----BEGIN [A-Z ]*CERTIFICATE REQUEST-----", "")
                    .replaceAll("-----END [A-Z ]*CERTIFICATE REQUEST-----", "")
                    .replaceAll("\\s", "");
            return new PKCS10CertificationRequest(Base64.getDecoder().decode(base64));
        } catch (Exception e) {
            throw new PermanentAgentException("EJBCA_CSR_INVALID",
                    "Could not parse the supplied CSR: " + e.getMessage(), e);
        }
    }
}
