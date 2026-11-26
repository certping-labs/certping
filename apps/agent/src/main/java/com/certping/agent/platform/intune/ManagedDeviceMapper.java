// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.model.message.DeviceIdentityEntry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Turns a raw Graph {@code managedDevice} into a normalised {@link DeviceIdentityEntry},
 * joining in the Entra device object.
 *
 * <p>Normalisation is not cosmetic. Verified against a live Intune tenant, Graph expresses
 * "no value" in at least five ways and is inconsistent between endpoints:
 * <ul>
 *   <li>empty strings rather than null — a stale enrollment returns {@code serialNumber: ""}</li>
 *   <li>the literal {@code "Unknown"} for device category</li>
 *   <li>{@code "0.0.0.0"} for an unreported OS version</li>
 *   <li>sentinel dates {@code 0001-01-01} and {@code 9999-12-31}</li>
 *   <li>an all-zero GUID for a device that is not Entra-registered</li>
 * </ul>
 * and the same field differs by endpoint: {@code udid} is null from the collection and
 * {@code ""} from a single GET. Left raw, the server would store sentinel junk, an empty serial
 * would break pre-registration matching, and change detection would flag every device on
 * every sync.
 */
@Slf4j
@Component
public class ManagedDeviceMapper {

    private static final String ZERO_GUID = "00000000-0000-0000-0000-000000000000";
    private static final Set<String> SENTINELS = Set.of("unknown", "0.0.0.0", "none");

    /** @param entraByDeviceId Entra devices keyed by {@code deviceId}, fetched once per run */
    public DeviceIdentityEntry toEntry(Map<String, Object> managedDevice,
                                       Map<String, Map<String, Object>> entraByDeviceId) {

        String azureAdDeviceId = guid(str(managedDevice, "azureADDeviceId"));
        Map<String, Object> entra = azureAdDeviceId == null
                ? Map.of()
                : entraByDeviceId.getOrDefault(azureAdDeviceId, Map.of());

        DeviceIdentityEntry.DeviceIdentityEntryBuilder builder = DeviceIdentityEntry.builder()
                .externalId(text(str(managedDevice, "id")))
                .entraObjectId(guid(str(entra, "id")))
                .entraDeviceId(azureAdDeviceId)
                .serialNumber(text(str(managedDevice, "serialNumber")))

                .deviceName(text(str(managedDevice, "deviceName")))
                .managedDeviceName(text(str(managedDevice, "managedDeviceName")))
                .operatingSystem(text(str(managedDevice, "operatingSystem")))
                .osVersion(textOrSentinel(str(managedDevice, "osVersion")))
                .manufacturer(text(str(managedDevice, "manufacturer")))
                .model(text(str(managedDevice, "model")))
                .deviceCategory(textOrSentinel(str(managedDevice, "deviceCategoryDisplayName")))
                .enrollmentProfileName(text(str(managedDevice, "enrollmentProfileName")))

                // Device identifiers are useful for future certificate matching and
                // remain in the endpoint vendor facet. They are not owner PII.
                .imei(text(str(managedDevice, "imei")))
                .meid(text(str(managedDevice, "meid")))
                .wifiMac(text(str(managedDevice, "wiFiMacAddress")))

                .ownerType(upper(textOrSentinel(str(managedDevice, "managedDeviceOwnerType"))))

                .complianceState(text(str(managedDevice, "complianceState")))
                .registrationState(text(str(managedDevice, "deviceRegistrationState")))
                .managementAgent(text(str(managedDevice, "managementAgent")))
                // From the Entra object. Preferred over Entra's isManaged/isCompliant/trustType,
                // all of which came back null on a genuinely managed device in live testing
                // while being populated on unmanaged personal phones.
                .managementType(text(str(entra, "managementType")))
                .deviceOwnership(text(str(entra, "deviceOwnership")))
                .enrollmentType(text(str(entra, "enrollmentType")))
                .isEncrypted(bool(managedDevice.get("isEncrypted")))
                .isSupervised(bool(managedDevice.get("isSupervised")))
                // Not textOrSentinel: "Unknown" is a genuine tri-state reading here, and is
                // in fact what a healthy, compliant, supervised device reports.
                .jailbrokenState(text(str(managedDevice, "jailBroken")))
                .mdmEnrolledAt(timestamp(str(managedDevice, "enrolledDateTime")))
                .mdmLastSyncAt(timestamp(str(managedDevice, "lastSyncDateTime")))

                .providerAttributes(sanitizeProviderAttributes(managedDevice));

        return builder.build();
    }

    private Map<String, Object> sanitizeProviderAttributes(Map<String, Object> managedDevice) {
        Map<String, Object> safe = new LinkedHashMap<>();
        putIfPresent(safe, "managementState", text(str(managedDevice, "managementState")));
        putIfPresent(safe, "easActivated", bool(managedDevice.get("easActivated")));
        putIfPresent(safe, "azureADRegistered", bool(managedDevice.get("azureADRegistered")));
        putIfPresent(safe, "deviceCategory",
                textOrSentinel(str(managedDevice, "deviceCategoryDisplayName")));
        putIfPresent(safe, "enrollmentProfileName",
                text(str(managedDevice, "enrollmentProfileName")));
        putIfPresent(safe, "exchangeAccessState",
                textOrSentinel(str(managedDevice, "exchangeAccessState")));
        putIfPresent(safe, "exchangeAccessStateReason",
                textOrSentinel(str(managedDevice, "exchangeAccessStateReason")));
        putIfPresent(safe, "partnerReportedThreatState",
                text(str(managedDevice, "partnerReportedThreatState")));
        putIfPresent(safe, "requireUserEnrollmentApproval",
                bool(managedDevice.get("requireUserEnrollmentApproval")));
        putIfPresent(safe, "managementCertificateExpiresAt",
                timestamp(str(managedDevice, "managementCertificateExpirationDate")));
        putIfPresent(safe, "complianceGracePeriodExpiresAt",
                timestamp(str(managedDevice, "complianceGracePeriodExpirationDateTime")));
        putIfPresent(safe, "androidSecurityPatchLevel",
                text(str(managedDevice, "androidSecurityPatchLevel")));
        return safe;
    }

    private static void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    // ── normalisation helpers ────────────────────────────────────────────────

    private String str(Map<String, Object> source, String key) {
        Object value = source.get(key);
        return value == null ? null : value.toString();
    }

    private String text(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String textOrSentinel(String value) {
        String normalized = text(value);
        if (normalized == null) return null;
        return SENTINELS.contains(normalized.toLowerCase()) ? null : normalized;
    }

    private String upper(String value) {
        return value == null ? null : value.toUpperCase();
    }

    /** An all-zero GUID means "not Entra-registered", not an identifier. */
    private String guid(String value) {
        String normalized = text(value);
        if (normalized == null) return null;
        return ZERO_GUID.equalsIgnoreCase(normalized) ? null : normalized;
    }

    /**
     * Drops sentinel dates and truncates to seconds.
     *
     * <p>Truncation matters: the collection endpoint returns second precision while a
     * single-device GET returns sub-second, so untruncated values make the same unchanged
     * device diff as changed depending on which call fetched it.
     */
    private String timestamp(String value) {
        String normalized = text(value);
        if (normalized == null) return null;
        try {
            OffsetDateTime parsed = OffsetDateTime.parse(normalized);
            int year = parsed.getYear();
            if (year <= 2 || year >= 9998) {
                return null;
            }
            return parsed.truncatedTo(ChronoUnit.SECONDS).toString();
        } catch (DateTimeParseException ex) {
            log.debug("Unparseable Graph timestamp '{}', treating as absent", normalized);
            return null;
        }
    }

    private Boolean bool(Object value) {
        if (value == null) return null;
        if (value instanceof Boolean b) return b;
        return Boolean.parseBoolean(value.toString());
    }
}
