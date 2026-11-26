// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.CertificateProfileMessage;
import com.certping.agent.model.message.ProfileObservedState;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

@Component
public class IntuneCertificateProfileMapper {
    private static final String WINDOWS_SCEP =
            "#microsoft.graph.windows81SCEPCertificateProfile";
    private static final String WINDOWS_TRUSTED_ROOT =
            "#microsoft.graph.windows81TrustedRootCertificate";
    private static final int MAX_ASSIGNMENT_GROUPS = 20;
    private static final Pattern GUID = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private final Clock clock;

    public IntuneCertificateProfileMapper(Clock clock) {
        this.clock = clock;
    }

    public Map<String, Object> toWindowsScepPayload(
            CertificateProfileMessage message, List<String> scepServerUrls) {
        if (!"WINDOWS".equalsIgnoreCase(message.getTargetPlatform())
                || !"SCEP".equalsIgnoreCase(message.getEnrollmentMethod())
                || !WINDOWS_SCEP.equals(message.getProviderProfileType())) {
            throw new PermanentAgentException("PROFILE_TYPE_UNSUPPORTED",
                    "Intune profile mutation currently supports Windows SCEP only");
        }
        if (scepServerUrls == null || scepServerUrls.isEmpty()) {
            throw new PermanentAgentException("SCEP_ENDPOINT_NOT_CONFIGURED",
                    "The agent SCEP listener has no advertised endpoint");
        }
        scepServerUrls.forEach(IntuneCertificateProfileMapper::validateScepUrl);
        Map<String, Object> configuration = requiredMap(message.getConfiguration(), "configuration");
        Map<String, Object> provider = nestedMap(configuration.get("providerConfig"));

        int keySize = requiredInt(configuration.get("keySize"), "keySize");
        int validityValue = requiredInt(configuration.get("validityValue"), "validityValue");
        int renewalPercentage = requiredInt(
                provider.get("renewalThresholdPercentage"), "renewalThresholdPercentage");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("@odata.type", WINDOWS_SCEP);
        payload.put("displayName", required(message.getName(), "name"));
        payload.put("description", description(message));
        payload.put("renewalThresholdPercentage", renewalPercentage);
        payload.put("keyStorageProvider", requiredString(
                provider.get("keyStorageProvider"), "keyStorageProvider"));
        payload.put("subjectNameFormat", "custom");
        payload.put("subjectNameFormatString", requiredString(
                configuration.get("subjectNameFormat"), "subjectNameFormat"));
        payload.put("certificateValidityPeriodValue", validityValue);
        payload.put("certificateValidityPeriodScale", requiredString(
                configuration.get("validityUnit"), "validityUnit").toLowerCase(Locale.ROOT));
        payload.put("extendedKeyUsages", normalizeExtendedKeyUsages(
                configuration.get("extendedKeyUsages")));
        List<Map<String, Object>> subjectAlternativeNames = normalizeSans(
                configuration.get("subjectAltNameFormats"));
        payload.put("customSubjectAlternativeNames", subjectAlternativeNames);
        payload.put("subjectAlternativeNameType", subjectAlternativeNameType(
                subjectAlternativeNames));
        payload.put("scepServerUrls", scepServerUrls);
        payload.put("keyUsage", keyUsage(configuration.get("keyUsages")));
        payload.put("keySize", "size" + keySize);
        payload.put("hashAlgorithm", graphHash(configuration.get("signatureHash")));
        String certificateScope = requiredString(
                configuration.get("certificateScope"), "certificateScope");
        payload.put("certificateStore", switch (certificateScope.toUpperCase(Locale.ROOT)) {
            case "DEVICE" -> "machine";
            case "USER" -> "user";
            default -> throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    "certificateScope must be DEVICE or USER");
        });
        return payload;
    }

    public Map<String, Object> toWindowsTrustedRootPayload(
            CertificateProfileMessage message, String marker, X509Certificate root) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("@odata.type", WINDOWS_TRUSTED_ROOT);
        payload.put("displayName", required(message.getName(), "name") + " (trusted root)");
        payload.put("description", IntuneProfileMarker.appendTo(null, marker));
        payload.put("trustedRootCertificate", Base64.getEncoder().encodeToString(encoded(root)));
        payload.put("certFileName", "certping-scep-root.cer");
        payload.put("destinationStore", "computerCertStoreRoot");
        return payload;
    }

    /** True when the Graph profile already carries exactly this root certificate. */
    public boolean holdsTrustedRoot(Map<String, Object> raw, X509Certificate root) {
        String current = string(raw.get("trustedRootCertificate"));
        if (current == null) {
            return false;
        }
        try {
            return Arrays.equals(Base64.getDecoder().decode(current), encoded(root));
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    /** Null when the key is absent, so the profile's Intune assignments are left untouched. */
    public List<String> assignmentGroupIds(CertificateProfileMessage message) {
        Map<String, Object> configuration = message.getConfiguration() == null
                ? Map.of() : message.getConfiguration();
        Object value = nestedMap(configuration.get("providerConfig")).get("assignmentGroupIds");
        if (value == null) {
            return null;
        }
        if (!(value instanceof List<?> values) || values.size() > MAX_ASSIGNMENT_GROUPS) {
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    "assignmentGroupIds must be a list of at most " + MAX_ASSIGNMENT_GROUPS + " groups");
        }
        List<String> groupIds = new ArrayList<>();
        for (Object item : values) {
            String groupId = string(item);
            if (groupId == null || !GUID.matcher(groupId).matches()) {
                throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                        "assignmentGroupIds must contain Entra group object IDs");
            }
            groupIds.add(groupId.toLowerCase(Locale.ROOT));
        }
        return groupIds.stream().distinct().toList();
    }

    public ProfileObservedState fromGraph(Map<String, Object> raw) {
        return fromGraph(raw, true);
    }

    public ProfileObservedState fromGraphForDiscovery(Map<String, Object> raw) {
        return fromGraph(raw, false);
    }

    private ProfileObservedState fromGraph(Map<String, Object> raw, boolean strict) {
        String type = requiredString(raw.get("@odata.type"), "@odata.type");
        String description = string(raw.get("description"));
        Map<String, Object> configuration = new LinkedHashMap<>();
        String certificateStore = string(raw.get("certificateStore"));
        if (certificateStore != null) {
            String certificateScope = switch (certificateStore.toLowerCase(Locale.ROOT)) {
                case "machine" -> "DEVICE";
                case "user" -> "USER";
                default -> {
                    if (strict) {
                        throw new PermanentAgentException("PROFILE_RESPONSE_INVALID",
                                "Intune returned an unsupported certificate store");
                    }
                    yield null;
                }
            };
            put(configuration, "certificateScope", certificateScope);
        }
        Integer keySize = parseKeySize(raw.get("keySize"));
        if (keySize != null) {
            configuration.put("keyAlgorithm", "RSA");
            configuration.put("keySize", keySize);
        }
        put(configuration, "signatureHash", normalizedHash(raw.get("hashAlgorithm")));
        put(configuration, "subjectNameFormat", raw.get("subjectNameFormatString"));
        configuration.put("subjectAltNameFormats",
                observedSans(raw.get("customSubjectAlternativeNames"), strict));
        configuration.put("extendedKeyUsages", list(raw.get("extendedKeyUsages")));
        configuration.put("keyUsages", splitKeyUsage(raw.get("keyUsage")));
        put(configuration, "validityValue", raw.get("certificateValidityPeriodValue"));
        put(configuration, "validityUnit", upper(raw.get("certificateValidityPeriodScale")));
        Map<String, Object> providerConfig = new LinkedHashMap<>();
        put(providerConfig, "renewalThresholdPercentage", raw.get("renewalThresholdPercentage"));
        put(providerConfig, "keyStorageProvider", raw.get("keyStorageProvider"));
        providerConfig.put("scepServerHosts", scepHosts(raw.get("scepServerUrls")));
        configuration.put("providerConfig", providerConfig);

        return ProfileObservedState.builder()
                .providerProfileId(requiredString(raw.get("id"), "id"))
                .providerProfileType(type)
                .providerCorrelationMarker(IntuneProfileMarker.extract(description))
                .name(requiredString(raw.get("displayName"), "displayName"))
                .description(description)
                .targetPlatform(targetPlatform(type))
                .targetVariant(targetVariant(type))
                .profileKind(profileKind(type))
                .enrollmentMethod(enrollmentMethod(type))
                .configuration(configuration)
                .providerResponse(safeSnapshot(raw, providerConfig))
                .providerVersion(string(raw.get("version")))
                .providerLastModifiedAt(string(raw.get("lastModifiedDateTime")))
                .observedAt(OffsetDateTime.now(clock).toString())
                .build();
    }

    private static Map<String, Object> safeSnapshot(
            Map<String, Object> raw, Map<String, Object> providerConfig) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (String key : List.of("@odata.type", "id", "displayName", "description",
                "createdDateTime", "lastModifiedDateTime", "version", "renewalThresholdPercentage",
                "keyStorageProvider", "subjectNameFormat", "subjectNameFormatString",
                "subjectAlternativeNameType", "subjectAlternativeNameFormatString",
                "certificateValidityPeriodValue", "certificateValidityPeriodScale",
                "extendedKeyUsages", "customSubjectAlternativeNames", "keyUsage", "keySize",
                "hashAlgorithm", "certificateStore")) {
            put(result, key, raw.get(key));
        }
        result.put("scepServerHosts", providerConfig.get("scepServerHosts"));
        return result;
    }

    private static List<Map<String, Object>> normalizeSans(Object value) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> values)) {
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    "subjectAltNameFormats must be an array");
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : values) {
            if (!(item instanceof Map<?, ?> map)) {
                throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                        "Every subject alternative name must be an object");
            }
            String type = requiredString(first(map, "sanType", "type"),
                    "subjectAltNameFormats.type");
            String name = requiredString(first(map, "name", "value", "format"),
                    "subjectAltNameFormats.format");
            result.add(Map.of("sanType", graphSanType(type), "name", name));
        }
        return result;
    }

    private static List<Map<String, Object>> observedSans(Object value, boolean strict) {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> values)) {
            throw new PermanentAgentException("PROFILE_RESPONSE_INVALID",
                    "Intune returned a non-array subject alternative name value");
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : values) {
            if (!(item instanceof Map<?, ?> map)) {
                throw new PermanentAgentException("PROFILE_RESPONSE_INVALID",
                        "Intune returned a non-object subject alternative name");
            }
            String providerType = requiredProviderString(
                    first(map, "sanType", "type"), "customSubjectAlternativeNames.sanType");
            String format = requiredProviderString(
                    first(map, "name", "value", "format"), "customSubjectAlternativeNames.name");
            String neutralType = providerNeutralSanType(providerType, strict);
            Map<String, Object> observed = new LinkedHashMap<>();
            observed.put("type", neutralType);
            observed.put("format", format);
            if ("OTHER".equals(neutralType)) {
                observed.put("providerType", providerType);
            }
            result.add(observed);
        }
        return result;
    }

    private static String subjectAlternativeNameType(List<Map<String, Object>> values) {
        if (values.isEmpty()) {
            return "none";
        }
        return values.stream()
                .map(value -> value.get("sanType").toString())
                .distinct()
                .sorted()
                .collect(java.util.stream.Collectors.joining(","));
    }

    private static List<Map<String, Object>> normalizeExtendedKeyUsages(Object value) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list(value)) {
            if (!(item instanceof Map<?, ?> map)) {
                continue;
            }
            String oid = string(first(map, "objectIdentifier", "oid"));
            if (oid == null || !oid.matches("[0-2](\\.[0-9]+)+")) {
                throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                        "Every extended key usage requires a valid objectIdentifier");
            }
            Map<String, Object> eku = new LinkedHashMap<>();
            eku.put("objectIdentifier", oid);
            put(eku, "name", first(map, "name"));
            result.add(eku);
        }
        return result;
    }

    private static String description(CertificateProfileMessage message) {
        return IntuneProfileMarker.appendTo(
                message.getDescription(), message.getProviderCorrelationMarker());
    }

    private static String targetPlatform(String type) {
        String normalized = type.toLowerCase(Locale.ROOT);
        if (normalized.contains("windows")) return "WINDOWS";
        if (normalized.contains("android")) return "ANDROID";
        if (normalized.contains("ios")) return "IOS_IPADOS";
        if (normalized.contains("macos")) return "MACOS";
        return "UNKNOWN";
    }

    private static String targetVariant(String type) {
        String normalized = type.toLowerCase(Locale.ROOT);
        if (normalized.contains("deviceowner")) return "DEVICE_OWNER";
        if (normalized.contains("workprofile")) return "WORK_PROFILE";
        if (normalized.contains("aosp")) return "AOSP";
        return "STANDARD";
    }

    private static String profileKind(String type) {
        String normalized = type.toLowerCase(Locale.ROOT);
        return normalized.contains("trusted") && normalized.contains("certificate")
                ? "TRUST_ANCHOR" : "CERTIFICATE_ENROLLMENT";
    }

    private static String enrollmentMethod(String type) {
        String normalized = type.toLowerCase(Locale.ROOT);
        if (normalized.contains("scep")) return "SCEP";
        if (normalized.contains("pkcs")) return "PKCS";
        return "NONE";
    }

    private static String keyUsage(Object value) {
        List<?> usages = list(value);
        return usages.isEmpty() ? "digitalSignature"
                : String.join(",", usages.stream().map(Object::toString).toList());
    }

    private static List<String> splitKeyUsage(Object value) {
        String raw = string(value);
        return raw == null ? List.of()
                : List.of(raw.split(",")).stream().map(String::trim).filter(v -> !v.isBlank()).toList();
    }

    private static String graphHash(Object value) {
        String normalized = upper(value);
        if (normalized == null || (!"SHA2".equals(normalized) && !"SHA256".equals(normalized))) {
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    "Intune Windows SCEP requires signatureHash SHA2");
        }
        return "sha2";
    }

    private static String normalizedHash(Object value) {
        return "sha2".equalsIgnoreCase(string(value)) ? "SHA2" : upper(value);
    }

    private static String graphSanType(String value) {
        return switch (value.toUpperCase(Locale.ROOT)) {
            case "EMAIL", "EMAIL_ADDRESS" -> "emailAddress";
            case "UPN", "USER_PRINCIPAL_NAME" -> "userPrincipalName";
            case "DNS", "DNS_NAME" -> "domainNameService";
            case "URI", "UNIFORM_RESOURCE_IDENTIFIER" -> "universalResourceIdentifier";
            default -> throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    "Unsupported Intune subject alternative name type");
        };
    }

    private static String providerNeutralSanType(String value, boolean strict) {
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "emailaddress" -> "EMAIL";
            case "userprincipalname" -> "UPN";
            case "domainnameservice" -> "DNS";
            case "universalresourceidentifier" -> "URI";
            default -> {
                if (strict) {
                    throw new PermanentAgentException("PROFILE_RESPONSE_INVALID",
                            "Intune returned an unsupported subject alternative name type");
                }
                yield "OTHER";
            }
        };
    }

    private static List<String> scepHosts(Object value) {
        List<String> result = new ArrayList<>();
        for (Object item : list(value)) {
            try {
                URI uri = URI.create(item.toString());
                if (uri.getHost() != null) {
                    result.add(uri.getHost());
                }
            } catch (IllegalArgumentException ignored) {
                // Invalid provider values are omitted from the safe snapshot.
            }
        }
        return result;
    }

    private static void validateScepUrl(String value) {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new PermanentAgentException("SCEP_ENDPOINT_INVALID",
                    "Configured SCEP server URL is invalid", exception);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new PermanentAgentException("SCEP_ENDPOINT_INVALID",
                    "Configured SCEP server URL must use HTTPS without user-info or a fragment");
        }
    }

    private static Integer parseKeySize(Object value) {
        String raw = string(value);
        if (raw == null || !raw.toLowerCase(Locale.ROOT).startsWith("size")) {
            return null;
        }
        try {
            return Integer.valueOf(raw.substring(4));
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static byte[] encoded(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException exception) {
            throw new PermanentAgentException("SCEP_CA_CHAIN_INVALID",
                    "The SCEP CA root certificate cannot be encoded", exception);
        }
    }

    private static Map<String, Object> requiredMap(Map<String, Object> value, String field) {
        if (value == null) {
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID", field + " is required");
        }
        return value;
    }

    private static Map<String, Object> nestedMap(Object value) {
        if (!(value instanceof Map<?, ?> raw)) {
            return Map.of();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        raw.forEach((key, nested) -> {
            if (key != null) result.put(key.toString(), nested);
        });
        return result;
    }

    private static List<?> list(Object value) {
        return value instanceof List<?> list ? list : List.of();
    }

    private static Object first(Map<?, ?> map, String... keys) {
        for (String key : keys) {
            if (map.containsKey(key)) return map.get(key);
        }
        return null;
    }

    private static int requiredInt(Object value, String field) {
        if (value instanceof Number number) {
            double candidate = number.doubleValue();
            if (Double.isFinite(candidate) && candidate == Math.rint(candidate)
                    && candidate >= Integer.MIN_VALUE && candidate <= Integer.MAX_VALUE) {
                return (int) candidate;
            }
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    field + " must be an integer");
        }
        try {
            return Integer.parseInt(requiredString(value, field));
        } catch (NumberFormatException exception) {
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID",
                    field + " must be an integer", exception);
        }
    }

    private static String requiredString(Object value, String field) {
        return required(string(value), field);
    }

    private static String requiredProviderString(Object value, String field) {
        String text = string(value);
        if (text == null) {
            throw new PermanentAgentException("PROFILE_RESPONSE_INVALID",
                    "Intune response field " + field + " is required");
        }
        return text;
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new PermanentAgentException("PROFILE_CONFIGURATION_INVALID", field + " is required");
        }
        return value.trim();
    }

    private static String string(Object value) {
        return value == null || value.toString().isBlank() ? null : value.toString().trim();
    }

    private static String upper(Object value) {
        String text = string(value);
        return text == null ? null : text.toUpperCase(Locale.ROOT);
    }

    private static void put(Map<String, Object> target, String key, Object value) {
        if (value != null) target.put(key, value);
    }
}
