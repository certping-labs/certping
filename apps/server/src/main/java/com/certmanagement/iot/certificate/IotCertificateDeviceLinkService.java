// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.entity.IotDevice;
import com.certmanagement.iot.entity.IotDeviceSource;
import com.certmanagement.iot.enums.DeviceEventType;
import com.certmanagement.iot.repository.IotDeviceRepository;
import com.certmanagement.iot.service.IotDeviceEventService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Resolves and audits device linkage for certificate enrollment, scoped to the resolved device
 * source and independent of any certificate profile.
 *
 * <p>An initial enrollment auto-links a device only from a {@code MICROSOFT_VALIDATED} identifier
 * of a supported namespace; a merely {@code ASSERTED} identifier is stored for investigation and
 * never linked — an unmatched certificate is safe, a certificate linked to the wrong device is
 * not. A renewal inherits linkage only from the exact prior certificate within the same source.
 */
@Service
@RequiredArgsConstructor
class IotCertificateDeviceLinkService {
    private static final String INITIAL = "INITIAL";
    private static final String RENEWAL = "RENEWAL";
    static final String NOT_ASSERTED = "NOT_ASSERTED";
    static final String MATCHED = "MATCHED";
    static final String DEVICE_NOT_SYNCED = "DEVICE_NOT_SYNCED";
    static final String IDENTIFIER_UNVERIFIED = "IDENTIFIER_UNVERIFIED";
    static final String AMBIGUOUS = "AMBIGUOUS";
    static final String INHERITED_FROM_RENEWAL = "INHERITED_FROM_RENEWAL";
    static final String RENEWAL_SOURCE_NOT_FOUND = "RENEWAL_SOURCE_NOT_FOUND";

    static final String ASSURANCE_MICROSOFT_VALIDATED = "MICROSOFT_VALIDATED";
    static final String ASSURANCE_ASSERTED = "ASSERTED";
    static final String TYPE_MANAGED_DEVICE_ID = "MANAGED_DEVICE_ID";
    static final String TYPE_UNKNOWN = "UNKNOWN";
    private static final Set<String> IDENTIFIER_TYPES = Set.of(
            TYPE_MANAGED_DEVICE_ID, "ENTRA_DEVICE_ID", "ENTRA_OBJECT_ID", "UNKNOWN");

    private final IotDeviceRepository deviceRepository;
    private final IotDeviceCertificateRepository certificateRepository;
    private final IotDeviceEventService eventService;

    DeviceLink resolve(IotDeviceSource source, ScepCertificateIssuedMessage message) {
        String enrollmentType = required(message.getEnrollmentType(), 20, "enrollmentType")
                .toUpperCase(Locale.ROOT);
        return switch (enrollmentType) {
            case INITIAL -> resolveInitial(source, message);
            case RENEWAL -> resolveRenewal(source, message);
            default -> throw new IllegalArgumentException("enrollmentType must be INITIAL or RENEWAL");
        };
    }

    void record(IotCertificateEnrollment enrollment, ScepCertificateIssuedMessage message,
                DeviceLink deviceLink, OffsetDateTime validatedAt) {
        if (NOT_ASSERTED.equals(deviceLink.status())) {
            return;
        }
        boolean linked = deviceLink.deviceId() != null;
        eventService.recordEnrollment(enrollment,
                linked ? DeviceEventType.CERTIFICATE_DEVICE_MATCHED
                        : DeviceEventType.CERTIFICATE_DEVICE_UNMATCHED,
                deviceLink.status(), eventMessage(deviceLink), eventDetail(deviceLink),
                message.getCorrelationId(),
                "scep-device-match:" + enrollment.getEnrollmentXref(), validatedAt);
    }

    private DeviceLink resolveInitial(IotDeviceSource source,
                                      ScepCertificateIssuedMessage message) {
        requireAbsent(message.getPriorCertificateIssuerDn(), "priorCertificateIssuerDn", INITIAL);
        requireAbsent(message.getPriorCertificateSerialNumber(),
                "priorCertificateSerialNumber", INITIAL);
        Identifier identifier = identifier(message);
        if (identifier == null) {
            return new DeviceLink(INITIAL, null, null, null, null, null, null, NOT_ASSERTED, null);
        }
        if (!ASSURANCE_MICROSOFT_VALIDATED.equals(identifier.assurance())) {
            // Visible in the request but not proven covered by Microsoft validation: store, never link.
            return unlinked(identifier, IDENTIFIER_UNVERIFIED);
        }
        if (TYPE_MANAGED_DEVICE_ID.equals(identifier.type())) {
            return deviceRepository.findRegisteredBySourceDeviceId(
                            source.getId(), identifier.value())
                    .map(device -> linked(identifier, device.getId()))
                    .orElseGet(() -> unlinked(identifier, DEVICE_NOT_SYNCED));
        }
        if (TYPE_UNKNOWN.equals(identifier.type())) {
            // Validated value, undetermined namespace: resolve it across the namespaces the source
            // actually stores. Exactly one device may answer to it — see resolveByAnyNamespace.
            return resolveByAnyNamespace(source, identifier);
        }
        // A namespace with no deterministic source-scoped lookup. Never guess across namespaces.
        return unlinked(identifier, IDENTIFIER_UNVERIFIED);
    }

    /**
     * Matches a validated identifier against every namespace stored for the source. A unique hit
     * links; anything else refuses — zero means the device has not synced yet, and two means the
     * identifier is ambiguous, which is exactly the situation where guessing puts a certificate on
     * the wrong device.
     */
    private DeviceLink resolveByAnyNamespace(IotDeviceSource source, Identifier identifier) {
        List<IotDevice> matches =
                deviceRepository.findRegisteredBySourceScopedIdentifier(
                        source.getId(), identifier.value());
        if (matches.size() == 1) {
            return linked(identifier, matches.get(0).getId());
        }
        return unlinked(identifier, matches.isEmpty() ? DEVICE_NOT_SYNCED : AMBIGUOUS);
    }

    private static DeviceLink linked(Identifier identifier, Long deviceId) {
        return new DeviceLink(INITIAL, identifier.value(), identifier.type(),
                identifier.assurance(), null, null, deviceId, MATCHED, null);
    }

    private static DeviceLink unlinked(Identifier identifier, String status) {
        return new DeviceLink(INITIAL, identifier.value(), identifier.type(),
                identifier.assurance(), null, null, null, status, null);
    }

    private DeviceLink resolveRenewal(IotDeviceSource source,
                                      ScepCertificateIssuedMessage message) {
        if (identifier(message) != null) {
            throw new IllegalArgumentException(
                    "a device identifier must be absent for RENEWAL enrollment");
        }
        String priorIssuer = required(
                message.getPriorCertificateIssuerDn(), 2000, "priorCertificateIssuerDn");
        String priorSerial = canonicalSerial(message.getPriorCertificateSerialNumber());
        String caProvider = required(message.getCaProvider(), 50, "caProvider").toUpperCase(Locale.ROOT);
        return certificateRepository
                .findByOrganizationIdAndCaProviderAndIssuerDnAndSerialNumber(
                        source.getOrganizationId(), caProvider, priorIssuer, priorSerial)
                // A prior certificate from another source must not leak linkage across routes.
                .filter(certificate -> source.getId().equals(certificate.getDeviceSourceId()))
                .map(certificate -> new DeviceLink(RENEWAL, null, null, null, priorIssuer, priorSerial,
                        certificate.getDeviceId(), INHERITED_FROM_RENEWAL,
                        certificate.getCertificateXref()))
                .orElseGet(() -> new DeviceLink(RENEWAL, null, null, null, priorIssuer, priorSerial,
                        null, RENEWAL_SOURCE_NOT_FOUND, null));
    }

    /** Normalizes and bounds the message's identifier; null when no identifier travelled at all. */
    private static Identifier identifier(ScepCertificateIssuedMessage message) {
        ScepCertificateIssuedMessage.DeviceIdentifier explicit = message.getDeviceIdentifier();
        if (explicit == null || explicit.getValue() == null || explicit.getValue().isBlank()) {
            return null;
        }
        String value = required(explicit.getValue(), 500, "deviceIdentifier.value");
        String type = required(explicit.getType(), 30, "deviceIdentifier.type")
                .toUpperCase(Locale.ROOT);
        if (!IDENTIFIER_TYPES.contains(type)) {
            throw new IllegalArgumentException("deviceIdentifier.type is not supported");
        }
        String assurance = required(explicit.getAssurance(), 30, "deviceIdentifier.assurance")
                .toUpperCase(Locale.ROOT);
        if (!ASSURANCE_MICROSOFT_VALIDATED.equals(assurance)
                && !ASSURANCE_ASSERTED.equals(assurance)) {
            throw new IllegalArgumentException("deviceIdentifier.assurance is not supported");
        }
        return new Identifier(value, type, assurance);
    }

    private record Identifier(String value, String type, String assurance) {
    }

    private static String eventMessage(DeviceLink deviceLink) {
        return switch (deviceLink.status()) {
            case MATCHED -> "Certificate enrollment matched to a managed device";
            case DEVICE_NOT_SYNCED ->
                    "Validated device identifier is not in the inventory yet; re-linked after sync";
            case IDENTIFIER_UNVERIFIED ->
                    "Device identifier stored without linking: provenance is not Microsoft-validated";
            case AMBIGUOUS ->
                    "Validated device identifier matches more than one device in this source";
            case INHERITED_FROM_RENEWAL -> deviceLink.deviceId() == null
                    ? "Renewal source certificate found without an existing device linkage"
                    : "Renewal device linkage inherited from the exact prior certificate";
            case RENEWAL_SOURCE_NOT_FOUND ->
                    "Exact prior certificate was not found for renewal device linkage";
            default -> throw new IllegalArgumentException("unsupported device match status");
        };
    }

    private static Map<String, Object> eventDetail(DeviceLink deviceLink) {
        Map<String, Object> detail = new LinkedHashMap<>();
        if (deviceLink.identifierValue() != null) {
            detail.put("identifierValue", deviceLink.identifierValue());
            detail.put("identifierType", deviceLink.identifierType());
            detail.put("identifierAssurance", deviceLink.identifierAssurance());
        }
        if (deviceLink.priorCertificateIssuerDn() != null) {
            detail.put("priorCertificateIssuerDn", deviceLink.priorCertificateIssuerDn());
            detail.put("priorCertificateSerialNumber", deviceLink.priorCertificateSerialNumber());
        }
        if (deviceLink.sourceCertificateXref() != null) {
            detail.put("sourceCertificateXref", deviceLink.sourceCertificateXref());
        }
        return Map.copyOf(detail);
    }

    private static String canonicalSerial(String value) {
        String serial = required(value, 160, "priorCertificateSerialNumber")
                .replace(":", "").toUpperCase(Locale.ROOT);
        if (!serial.matches("[0-9A-F]+")) {
            throw new IllegalArgumentException("priorCertificateSerialNumber must be hexadecimal");
        }
        return serial;
    }

    private static String required(String value, int max, String field) {
        String normalized = value == null ? null : value.trim();
        if (normalized == null || normalized.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (normalized.length() > max) {
            throw new IllegalArgumentException(field + " exceeds " + max + " characters");
        }
        return normalized;
    }

    private static void requireAbsent(String value, String field, String enrollmentType) {
        if (value != null && !value.isBlank()) {
            throw new IllegalArgumentException(
                    field + " must be absent for " + enrollmentType + " enrollment");
        }
    }

    record DeviceLink(String enrollmentType, String identifierValue, String identifierType,
                      String identifierAssurance, String priorCertificateIssuerDn,
                      String priorCertificateSerialNumber, Long deviceId, String status,
                      String sourceCertificateXref) {
    }
}
