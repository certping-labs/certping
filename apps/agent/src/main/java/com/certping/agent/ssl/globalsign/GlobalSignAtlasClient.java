// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.globalsign;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.Locale;

@Slf4j
@Component
@RequiredArgsConstructor
public class GlobalSignAtlasClient {

    private static final String JSON_CONTENT_TYPE = "application/json;charset=utf-8";

    private final AgentProperties properties;
    private final ObjectMapper objectMapper;

    private volatile HttpClient httpClient;
    private volatile String cachedToken;
    private volatile Instant tokenExpiresAt = Instant.EPOCH;

    public IssueResult issueCertificate(String domain, List<String> sanDomains, String csrPem) {
        JsonNode policy = null;
        try {
            policy = getValidationPolicy();
        } catch (Exception e) {
            // If policy fetch fails, continue with safe defaults.
            log.warn("GlobalSign validationpolicy fetch failed, continuing with defaults: {}", e.getMessage());
        }
        return issueCertificate(domain, sanDomains, csrPem, policy);
    }

    public IssueResult issueCertificate(String domain, List<String> sanDomains, String csrPem, JsonNode policy) {
        return issueCertificate(domain, sanDomains, csrPem, policy, null);
    }

    /**
     * @param validityDaysOverride optional user-requested validity. When null, sends
     *        {@code not_after=0} so Atlas picks the policy max (existing behaviour).
     *        When set, computes {@code not_after = not_before + N*86400}. Atlas
     *        rejects values above the validation-policy max; we surface that as a
     *        permanent error from {@code assert2xx}.
     */
    public IssueResult issueCertificate(String domain, List<String> sanDomains, String csrPem, JsonNode policy,
                                        Integer validityDaysOverride) {
        // - validity: per GlobalSign Atlas API doc (validation_policy.validity), not_before
        //   is unix-seconds and not_after=0 means "policy max". When the user supplies a
        //   per-cert override we compute a concrete not_after.
        // - public_key: send PKCS10 CSR PEM directly as a string
        long notBefore = Instant.now().getEpochSecond();
        validateUnsupportedPolicyRequirements(policy);

        Map<String, Object> signature = buildSignaturePayloadFromPolicy(policy);
        Map<String, Object> subjectDn = buildSubjectDnPayloadFromPolicy(policy, domain);

        // TLS certs must have the CN in the SAN dns_names list.
        // Always prepend the primary domain so sanDomains=[api.example.com] becomes
        // dns_names=[example.com, api.example.com].
        List<String> allSanDns = new ArrayList<>();
        // allSanDns.add(domain);
        if (sanDomains != null) allSanDns.addAll(sanDomains);
        Map<String, Object> sanPayload = buildSanPayloadFromPolicy(policy, allSanDns);

        List<String> ekuPayload = buildExtendedKeyUsagesFromPolicy(policy);
        Map<String, Object> keyUsages = buildKeyUsagesFromPolicy(policy);

        Map<String, Object> subjectDaPayload          = buildSubjectDaPayload(policy);
        Map<String, Object> qualifiedStatementsPayload = buildQualifiedStatementsPayload(policy);
        Map<String, Object> msTemplatePayload          = buildMsExtensionTemplatePayload(policy);
        Map<String, Object> customExtensionsPayload    = buildCustomExtensionsPayload(policy);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("validity", buildValidityPayloadFromPolicy(policy, notBefore, validityDaysOverride));
        payload.put("subject_dn", subjectDn);
        payload.put("san", sanPayload);
        payload.put("signature", signature);
        payload.put("extended_key_usages", ekuPayload);
        if (!keyUsages.isEmpty())              payload.put("key_usages", keyUsages);
        if (!subjectDaPayload.isEmpty())       payload.put("subject_da", subjectDaPayload);
        if (!qualifiedStatementsPayload.isEmpty()) payload.put("qualified_statements", qualifiedStatementsPayload);
        if (!msTemplatePayload.isEmpty())      payload.put("ms_extension_template", msTemplatePayload);
        if (!customExtensionsPayload.isEmpty()) payload.put("custom_extensions", customExtensionsPayload);
        payload.put("public_key", csrPem);

        String requestJson = toJson(payload);
        log.debug("GlobalSign POST /certificates request: {}", requestJson);
        HttpResponse<String> response = sendWithBearerRetry("POST", cfg().getIssuePath(), requestJson);

        String serial = extractSerial(response, parseJson(response.body()));
        if (serial == null || serial.isBlank()) {
            throw new PermanentAgentException("GLOBALSIGN_RESPONSE_INVALID",
                    "GlobalSign issue response did not include certificate serial");
        }
        return new IssueResult(serial);
    }

    private Map<String, Object> buildSignaturePayloadFromPolicy(JsonNode policy) {
        JsonNode sigOverrides = parseJsonEnv(cfg().getSignatureJson(), "AGENT_GLOBALSIGN_SIGNATURE_JSON");
        String preferredHash = sigOverrides != null ? sigOverrides.path("hash_algorithm").asString("SHA-256") : "SHA-256";
        String preferredAlg  = sigOverrides != null ? sigOverrides.path("algorithm").asString(null) : null;

        String hashAlg = preferredHash;
        String sigAlg  = null;

        if (policy != null) {
            JsonNode sig = policy.path("signature");
            JsonNode hashList = sig.path("hash_algorithm").path("list");
            if (hashList.isArray() && hashList.size() > 0) {
                boolean found = false;
                for (JsonNode n : hashList) {
                    if (preferredHash.equalsIgnoreCase(n.asString())) { found = true; break; }
                }
                if (!found) hashAlg = hashList.get(0).asString("SHA-256");
            }

            String algorithmPresence = sig.path("algorithm").path("presence").asString("");
            boolean includeAlgorithm = "REQUIRED".equalsIgnoreCase(algorithmPresence)
                    || "API_OVERRIDE".equalsIgnoreCase(algorithmPresence)
                    || "OPTIONAL_API_OVERRIDE".equalsIgnoreCase(algorithmPresence);
            JsonNode algList = sig.path("algorithm").path("list");
            if (includeAlgorithm && algList.isArray() && algList.size() > 0) {
                if (preferredAlg != null) {
                    for (JsonNode n : algList) {
                        if (preferredAlg.equalsIgnoreCase(n.asString())) { sigAlg = preferredAlg; break; }
                    }
                }
                if (sigAlg == null) {
                    for (JsonNode n : algList) {
                        if ("RSA".equalsIgnoreCase(n.asString())) { sigAlg = "RSA"; break; }
                    }
                }
                if (sigAlg == null) sigAlg = algList.get(0).asString(null);
            }
        } else if (preferredAlg != null) {
            sigAlg = preferredAlg;
        }

        return sigAlg != null
                ? Map.of("algorithm", sigAlg, "hash_algorithm", hashAlg)
                : Map.of("hash_algorithm", hashAlg);
    }

    private Map<String, Object> buildValidityPayloadFromPolicy(JsonNode policy, long notBefore,
                                                                Integer validityDaysOverride) {
        if (validityDaysOverride != null && validityDaysOverride > 0) {
            long notAfter = notBefore + (long) validityDaysOverride * 86_400L;
            return Map.of("not_before", notBefore, "not_after", notAfter);
        }
        // Default: not_after=0 → Atlas picks the policy max.
        return Map.of("not_before", notBefore, "not_after", 0);
    }

    private Map<String, Object> buildSubjectDnPayloadFromPolicy(JsonNode policy, String domain) {
        Map<String, Object> out = new LinkedHashMap<>();
        JsonNode subjectDn = policy != null ? policy.path("subject_dn") : null;
        JsonNode overrides = parseJsonEnv(cfg().getSubjectDnJson(), "AGENT_GLOBALSIGN_SUBJECT_DN_JSON");

        if (subjectDn == null || subjectDn.isMissingNode()) {
            out.put("common_name", domain);
            return out;
        }

        String cnPresence = subjectDn.path("common_name").path("presence").asString("OPTIONAL");
        if ("FORBIDDEN".equalsIgnoreCase(cnPresence)) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_UNSUPPORTED",
                    "GlobalSign policy forbids subject_dn.common_name, which is required by current agent issuance flow");
        }
        if ("STATIC".equalsIgnoreCase(cnPresence)) {
            // STATIC CN is applied by the CA from policy — do not send it in the request.
        } else {
            out.put("common_name", domain);
        }

        addSubjectDnStringField(out, subjectDn, overrides, "surname");
        addSubjectDnStringField(out, subjectDn, overrides, "given_name");
        addSubjectDnStringField(out, subjectDn, overrides, "organization");
        addSubjectDnStringField(out, subjectDn, overrides, "organization_identifier");
        addSubjectDnStringField(out, subjectDn, overrides, "country");
        addSubjectDnStringField(out, subjectDn, overrides, "state");
        addSubjectDnStringField(out, subjectDn, overrides, "locality");
        addSubjectDnStringField(out, subjectDn, overrides, "street_address");
        addSubjectDnStringField(out, subjectDn, overrides, "postal_code");
        addSubjectDnStringField(out, subjectDn, overrides, "email");
        addSubjectDnStringField(out, subjectDn, overrides, "pseudonym");
        addSubjectDnStringField(out, subjectDn, overrides, "jurisdiction_of_incorporation_locality_name");
        addSubjectDnStringField(out, subjectDn, overrides, "jurisdiction_of_incorporation_state_or_province_name");
        addSubjectDnStringField(out, subjectDn, overrides, "jurisdiction_of_incorporation_country_name");
        addSubjectDnStringField(out, subjectDn, overrides, "business_category");
        addSubjectDnStringField(out, subjectDn, overrides, "serial_number");

        JsonNode ouSpec = subjectDn.path("organizational_unit");
        if (ouSpec.isObject()) {
            List<String> requestedOu = jsonNodeToList(overrides != null ? overrides.path("organizational_unit") : null);
            List<String> finalOu = applyListPolicy(ouSpec, requestedOu, "subject_dn.organizational_unit");
            if (!finalOu.isEmpty()) out.put("organizational_unit", finalOu);
        }

        return out;
    }

    private void addSubjectDnStringField(Map<String, Object> out,
                                         JsonNode policyDn,
                                         JsonNode overrides,
                                         String field) {
        JsonNode spec = policyDn.path(field);
        if (!spec.isObject()) return;
        String presence = spec.path("presence").asString("OPTIONAL");
        String override = overrides != null && overrides.has(field) ? overrides.path(field).asString(null) : null;

        if ("FORBIDDEN".equalsIgnoreCase(presence)) return;
        if ("STATIC".equalsIgnoreCase(presence)) {
            // STATIC fields are applied by the CA from policy — do NOT send them in the request.
            // Sending them (even with the correct value) causes GlobalSign to reject with 400.
            // Same principle as STATIC_TRUE/STATIC_FALSE for key_usages.
            return;
        }
        if ("REQUIRED".equalsIgnoreCase(presence) || "API_OVERRIDE".equalsIgnoreCase(presence)) {
            if (isBlank(override)) {
                throw new PermanentAgentException("GLOBALSIGN_POLICY_REQUIRED_FIELD_MISSING",
                        "GlobalSign policy requires subject_dn." + field + " but no value in AGENT_GLOBALSIGN_SUBJECT_DN_JSON");
            }
            out.put(field, override.trim());
            return;
        }
        if (!isBlank(override)) out.put(field, override.trim());
    }

    private Map<String, Object> buildSanPayloadFromPolicy(JsonNode policy, List<String> sanDomains) {
        Map<String, Object> out = new LinkedHashMap<>();
        JsonNode san = policy != null ? policy.path("san") : null;
        JsonNode sanOverrides = parseJsonEnv(cfg().getSanJson(), "AGENT_GLOBALSIGN_SAN_JSON");

        List<String> requestedDns = sanDomains != null ? sanDomains : List.of();
        List<String> finalDns = san != null && san.isObject()
                ? applyListPolicy(san.path("dns_names"), requestedDns, "san.dns_names")
                : requestedDns;
        out.put("dns_names", finalDns);

        List<String> sanEmails = jsonNodeToList(sanOverrides != null ? sanOverrides.path("emails") : null);
        List<String> finalEmails = san != null && san.isObject()
                ? applyListPolicy(san.path("emails"), sanEmails, "san.emails")
                : sanEmails;
        if (!finalEmails.isEmpty()) out.put("emails", finalEmails);

        List<String> sanUris = jsonNodeToList(sanOverrides != null ? sanOverrides.path("uris") : null);
        List<String> finalUris = san != null && san.isObject()
                ? applyListPolicy(san.path("uris"), sanUris, "san.uris")
                : sanUris;
        if (!finalUris.isEmpty()) out.put("uris", finalUris);

        List<String> sanIps = jsonNodeToList(sanOverrides != null ? sanOverrides.path("ip_addresses") : null);
        List<String> finalIps = san != null && san.isObject()
                ? applyListPolicy(san.path("ip_addresses"), sanIps, "san.ip_addresses")
                : sanIps;
        if (!finalIps.isEmpty()) out.put("ip_addresses", finalIps);

        // other_names: pass through as-is from sanJson if supplied (complex type_and_value map).
        if (sanOverrides != null && sanOverrides.has("other_names") && !sanOverrides.path("other_names").isNull()) {
            out.put("other_names", jsonNodeToMap(sanOverrides.path("other_names")));
        }

        return out;
    }

    private List<String> buildExtendedKeyUsagesFromPolicy(JsonNode policy) {
        JsonNode ekus = policy != null ? policy.path("extended_key_usages").path("ekus") : null;
        JsonNode ekuOverrides = parseJsonEnv(cfg().getExtendedKeyUsagesJson(), "AGENT_GLOBALSIGN_EXTENDED_KEY_USAGES_JSON");
        List<String> fromEnv = ekuOverrides != null
                ? jsonNodeToList(ekuOverrides.has("ekus") ? ekuOverrides.path("ekus") : ekuOverrides)
                : List.of();
        List<String> requested = fromEnv.isEmpty() ? List.of("1.3.6.1.5.5.7.3.1") : fromEnv;

        if (ekus == null || !ekus.isObject()) {
            return requested;
        }

        List<String> allowed = toStringList(ekus.path("list"));
        List<String> filtered = new ArrayList<>();
        for (String value : requested) {
            if (matchesAnyPolicyPattern(value, allowed)) {
                filtered.add(value);
            }
        }
        if (filtered.isEmpty()) {
            // fall back to first allowed values up to mincount.
            filtered.addAll(allowed);
        }

        int min = ekus.path("mincount").asInt(0);
        int max = ekus.path("maxcount").asInt(Integer.MAX_VALUE);
        if (filtered.size() > max) {
            filtered = filtered.subList(0, max);
        }
        if (filtered.size() < min) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_REQUIRED_FIELD_MISSING",
                    "GlobalSign policy requires at least " + min + " extended_key_usages values");
        }
        return filtered;
    }

    private static final List<String> KEY_USAGE_FIELDS = List.of(
            "digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
            "key_agreement", "key_certificate_sign", "crl_sign", "encipher_only", "decipher_only");

    private Map<String, Object> buildKeyUsagesFromPolicy(JsonNode policy) {
        Map<String, Object> out = new LinkedHashMap<>();
        JsonNode keyUsages = policy != null ? policy.path("key_usages") : null;
        JsonNode kuOverrides = parseJsonEnv(cfg().getKeyUsagesJson(), "AGENT_GLOBALSIGN_KEY_USAGES_JSON");

        if (keyUsages == null || !keyUsages.isObject()) {
            // No policy — include whatever the env var says.
            if (kuOverrides != null && kuOverrides.isObject()) {
                for (String field : KEY_USAGE_FIELDS) {
                    if (kuOverrides.has(field)) out.put(field, kuOverrides.path(field).asBoolean());
                }
            }
            return out;
        }

        for (String field : KEY_USAGE_FIELDS) {
            String presence = keyUsages.path(field).asString("");
            // STATIC_TRUE / STATIC_FALSE are applied by the CA based on policy — do NOT send them in
            // the issuance request (sending false values causes GlobalSign to reject with 400).
            // Only include OPTIONAL bits when the operator has explicitly configured them.
            if ("OPTIONAL".equalsIgnoreCase(presence) && kuOverrides != null && kuOverrides.has(field)) {
                out.put(field, kuOverrides.path(field).asBoolean());
            }
        }

        return out;
    }

    private List<String> applyListPolicy(JsonNode spec, List<String> requested, String fieldName) {
        List<String> requestedSafe = requested != null ? requested : List.of();
        if (spec == null || !spec.isObject()) {
            return requestedSafe;
        }

        boolean isStatic = spec.path("static").asBoolean(false);
        int min = spec.path("mincount").asInt(0);
        int max = spec.path("maxcount").asInt(Integer.MAX_VALUE);
        List<String> policyList = toStringList(spec.path("list"));

        List<String> out = new ArrayList<>();
        if (isStatic) {
            out.addAll(policyList);
        } else {
            out.addAll(requestedSafe);
        }

        if (out.size() > max) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_LIST_OVERFLOW",
                    "Field " + fieldName + " has " + out.size() + " values but policy maxcount is " + max);
        }
        if (out.size() < min) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_REQUIRED_FIELD_MISSING",
                    "Field " + fieldName + " requires at least " + min + " value(s)");
        }

        return out;
    }

    private List<String> toStringList(JsonNode arr) {
        List<String> out = new ArrayList<>();
        if (arr != null && arr.isArray()) {
            for (JsonNode n : arr) {
                String v = n.asString("");
                if (!isBlank(v)) {
                    out.add(v);
                }
            }
        }
        return out;
    }

    private Map<String, Object> buildSubjectDaPayload(JsonNode policy) {
        // Only include subject_da if the validationpolicy declares this section.
        // Sending fields the CA policy does not define causes GlobalSign to return 400.
        if (!policyHasSection(policy, "subject_da")) return Map.of();
        JsonNode override = parseJsonEnv(cfg().getSubjectDaJson(), "AGENT_GLOBALSIGN_SUBJECT_DA_JSON");
        return jsonNodeToMap(override);
    }

    private Map<String, Object> buildQualifiedStatementsPayload(JsonNode policy) {
        if (!policyHasSection(policy, "qualified_statements")) return Map.of();
        JsonNode override = parseJsonEnv(cfg().getQualifiedStatementsJson(), "AGENT_GLOBALSIGN_QUALIFIED_STATEMENTS_JSON");
        return jsonNodeToMap(override);
    }

    private Map<String, Object> buildMsExtensionTemplatePayload(JsonNode policy) {
        if (!policyHasSection(policy, "ms_extension_template")) return Map.of();
        JsonNode override = parseJsonEnv(cfg().getMsExtensionTemplateJson(), "AGENT_GLOBALSIGN_MS_EXTENSION_TEMPLATE_JSON");
        return jsonNodeToMap(override);
    }

    private Map<String, Object> buildCustomExtensionsPayload(JsonNode policy) {
        if (!policyHasSection(policy, "custom_extensions")) return Map.of();
        JsonNode override = parseJsonEnv(cfg().getCustomExtensionsJson(), "AGENT_GLOBALSIGN_CUSTOM_EXTENSIONS_JSON");
        return jsonNodeToMap(override);
    }

    /**
     * Returns true when the validationpolicy JSON has a non-null, non-absent entry for {@code section}.
     * Used to guard optional sections (subject_da, qualified_statements, etc.) so that env-var
     * placeholder values are never sent to a CA whose policy doesn't declare the section.
     */
    private boolean policyHasSection(JsonNode policy, String section) {
        if (policy == null) return false;
        JsonNode node = policy.path(section);
        return !node.isMissingNode() && !node.isNull();
    }

    private JsonNode parseJsonEnv(String json, String envVarName) {
        if (isBlank(json)) return null;
        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            log.warn("Could not parse {} as JSON, ignoring: {}", envVarName, e.getMessage());
            return null;
        }
    }

    private List<String> jsonNodeToList(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) return List.of();
        if (node.isArray()) return toStringList(node);
        String text = node.asString("").trim();
        if (isBlank(text)) return List.of();
        List<String> out = new ArrayList<>();
        for (String part : text.split(",")) {
            String v = part.trim();
            if (!isBlank(v)) out.add(v);
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> jsonNodeToMap(JsonNode node) {
        if (node == null || !node.isObject()) return Map.of();
        try {
            return objectMapper.convertValue(node, Map.class);
        } catch (Exception e) {
            log.warn("Failed to convert JSON node to map: {}", e.getMessage());
            return Map.of();
        }
    }

    private boolean matchesAnyPolicyPattern(String value, List<String> patterns) {
        if (patterns == null || patterns.isEmpty()) {
            return true;
        }
        for (String pattern : patterns) {
            if (isBlank(pattern)) {
                continue;
            }
            if (pattern.startsWith("^") || pattern.endsWith("$")) {
                if (Pattern.compile(pattern).matcher(value).matches()) {
                    return true;
                }
            } else if (pattern.equalsIgnoreCase(value)) {
                return true;
            }
        }
        return false;
    }

    private void validateUnsupportedPolicyRequirements(JsonNode policy) {
        if (policy == null || !cfg().isStrictPolicyValidation()) {
            return;
        }

        JsonNode subjectDa = policy.path("subject_da");
        if (subjectDa != null && subjectDa.isObject() && sectionRequiresHandling(subjectDa)
                && isBlank(cfg().getSubjectDaJson())) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_UNSUPPORTED",
                    "GlobalSign policy requires subject_da — set AGENT_GLOBALSIGN_SUBJECT_DA_JSON to provide values");
        }

        JsonNode qualified = policy.path("qualified_statements");
        if (qualified != null && qualified.isObject() && sectionRequiresHandling(qualified)
                && isBlank(cfg().getQualifiedStatementsJson())) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_UNSUPPORTED",
                    "GlobalSign policy requires qualified_statements — set AGENT_GLOBALSIGN_QUALIFIED_STATEMENTS_JSON to provide values");
        }

        JsonNode msTemplate = policy.path("ms_extension_template");
        if (msTemplate != null && msTemplate.isObject() && sectionRequiresHandling(msTemplate)
                && isBlank(cfg().getMsExtensionTemplateJson())) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_UNSUPPORTED",
                    "GlobalSign policy requires ms_extension_template — set AGENT_GLOBALSIGN_MS_EXTENSION_TEMPLATE_JSON to provide values");
        }

        JsonNode custom = policy.path("custom_extensions");
        if (custom != null && custom.isObject() && sectionRequiresHandling(custom)
                && isBlank(cfg().getCustomExtensionsJson())) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_UNSUPPORTED",
                    "GlobalSign policy requires custom_extensions — set AGENT_GLOBALSIGN_CUSTOM_EXTENSIONS_JSON to provide values");
        }

        JsonNode otherNames = policy.path("san").path("other_names");
        if (!otherNames.isMissingNode() && !otherNames.isNull() && sectionRequiresHandling(otherNames)) {
            JsonNode sanOverrides = parseJsonEnv(cfg().getSanJson(), "AGENT_GLOBALSIGN_SAN_JSON");
            boolean supplied = sanOverrides != null && sanOverrides.has("other_names")
                    && !sanOverrides.path("other_names").isNull();
            if (!supplied) {
                throw new PermanentAgentException("GLOBALSIGN_POLICY_UNSUPPORTED",
                        "GlobalSign policy requires san.other_names — set 'other_names' inside AGENT_GLOBALSIGN_SAN_JSON to provide values");
            }
        }

        String publicKeySig = policy.path("public_key_signature").asString("");
        if ("REQUIRED".equalsIgnoreCase(publicKeySig)) {
            throw new PermanentAgentException("GLOBALSIGN_POLICY_UNSUPPORTED",
                    "GlobalSign policy requires public_key_signature, which is not supported by this agent flow yet");
        }
    }

    private boolean sectionRequiresHandling(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return false;
        }
        if (node.isString()) {
            String text = node.asString("");
            return "REQUIRED".equalsIgnoreCase(text)
                    || "STATIC".equalsIgnoreCase(text)
                    || "STATIC_TRUE".equalsIgnoreCase(text)
                    || "STATIC_FALSE".equalsIgnoreCase(text)
                    || "API_OVERRIDE".equalsIgnoreCase(text);
        }
        if (node.isBoolean()) {
            return node.asBoolean();
        }
        if (node.isNumber()) {
            return node.asInt() > 0;
        }
        if (node.isArray()) {
            for (JsonNode child : node) {
                if (sectionRequiresHandling(child)) {
                    return true;
                }
            }
            return false;
        }
        if (node.isObject()) {
            if (node.has("presence")) {
                String presence = node.path("presence").asString("");
                if ("REQUIRED".equalsIgnoreCase(presence)
                        || "STATIC".equalsIgnoreCase(presence)
                        || "API_OVERRIDE".equalsIgnoreCase(presence)) {
                    return true;
                }
            }
            if (node.has("mincount") && node.path("mincount").asInt(0) > 0) {
                return true;
            }
            if (node.has("critical") && node.path("critical").asBoolean(false)) {
                return true;
            }

            var it = node.properties().iterator();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                if (sectionRequiresHandling(e.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }

    public JsonNode getValidationPolicy() {
        HttpResponse<String> response = sendWithBearerRetry("GET", "/validationpolicy", null);
        return parseJson(response.body());
    }

    public DomainClaim initiateDomainClaim(String domain) {
        String normalizedDomain = domain != null ? domain.trim().toLowerCase(Locale.ROOT) : "";
        if (isBlank(normalizedDomain)) {
            throw new PermanentAgentException("GLOBALSIGN_DOMAIN_INVALID", "Domain claim requires a non-empty domain");
        }

        String path = "/claims/domains/" + encodePathSegment(normalizedDomain);
        HttpResponse<String> response = sendWithBearerRetry("POST", path, "{}");
        JsonNode body = parseJson(response.body());
        String token = body.path("token").asString(null);
        if (isBlank(token)) {
            throw new PermanentAgentException("GLOBALSIGN_RESPONSE_INVALID",
                    "GlobalSign claim response missing token for domain " + normalizedDomain);
        }

        String claimId = extractClaimId(response, body);
        if (isBlank(claimId)) {
            throw new PermanentAgentException("GLOBALSIGN_RESPONSE_INVALID",
                    "GlobalSign claim response missing claim ID for domain " + normalizedDomain);
        }
        return new DomainClaim(claimId, token, normalizedDomain);
    }

    /**
     * Returns the first VERIFIED claim ID for the given domain, or null if none exists.
     * Used to skip re-claiming a domain that is already verified on this account.
     */
    public String findVerifiedClaimId(String domain) {
        HttpResponse<String> response = sendWithBearerRetry(
                "GET", "/claims/domains?domain=" + encodePathSegment(domain) + "&status=VERIFIED&per_page=5", null);
        JsonNode body = parseJson(response.body());
        JsonNode claims = body.isArray() ? body : body.path("claims");
        if (claims.isArray()) {
            for (JsonNode claim : claims) {
                String d = claim.path("domain").asString("").replaceAll("\\.$", "");
                String domainNorm = domain.replaceAll("\\.$", "");
                if (domainNorm.equalsIgnoreCase(d) && "VERIFIED".equalsIgnoreCase(claim.path("status").asString(""))) {
                    return claim.path("id").asString(null);
                }
            }
        }
        return null;
    }

    /**
     * The account's PENDING claim for {@code domain}, with its token, or null. Atlas answers 409 to a second claim
     * POST for a domain, so a claim left PENDING by an earlier attempt must be reused rather than created again.
     */
    public DomainClaim findPendingClaim(String domain) {
        String domainNorm = domain.replaceAll("\\.$", "");
        HttpResponse<String> response = sendWithBearerRetry(
                "GET", "/claims/domains?domain=" + encodePathSegment(domainNorm) + "&status=PENDING&per_page=5", null);
        JsonNode body = parseJson(response.body());
        JsonNode claims = body.isArray() ? body : body.path("claims");
        if (!claims.isArray()) {
            return null;
        }
        for (JsonNode claim : claims) {
            String d = claim.path("domain").asString("").replaceAll("\\.$", "");
            String id = claim.path("id").asString(null);
            if (domainNorm.equalsIgnoreCase(d) && "PENDING".equalsIgnoreCase(claim.path("status").asString(""))
                    && !isBlank(id)) {
                String token = claim.path("token").asString(null);
                if (isBlank(token)) {
                    token = getDomainClaim(id).path("token").asString(null);
                }
                return isBlank(token) ? null : new DomainClaim(id, token, domainNorm);
            }
        }
        return null;
    }

    public void verifyDomainDns(String claimId, String authorizationDomain) {
        Map<String, Object> payload = Map.of("authorization_domain", authorizationDomain);
        sendWithBearerRetry("POST", "/claims/domains/" + claimId + "/dns", toJson(payload));
    }

    public JsonNode getDomainClaim(String claimId) {
        HttpResponse<String> response = sendWithBearerRetry("GET", "/claims/domains/" + claimId, null);
        return parseJson(response.body());
    }

    public JsonNode getCertificate(String serial) {
        HttpResponse<String> response = sendWithBearerRetry("GET", "/certificates/" + serial, null);
        return parseJson(response.body());
    }

    public String getTrustChainPem() {
        HttpResponse<String> response = sendWithBearerRetry("GET", cfg().getTrustChainPath(), null);
        JsonNode json = parseJson(response.body());
        if (json.isArray()) {
            List<String> certs = new ArrayList<>();
            json.forEach(node -> certs.add(node.asString("")));
            return String.join("\n", certs);
        }
        if (json.has("certificates") && json.get("certificates").isArray()) {
            List<String> certs = new ArrayList<>();
            json.get("certificates").forEach(node -> certs.add(node.asString("")));
            return String.join("\n", certs);
        }
        if (json.has("trust_chain") && json.get("trust_chain").isArray()) {
            List<String> certs = new ArrayList<>();
            json.get("trust_chain").forEach(node -> certs.add(node.asString("")));
            return String.join("\n", certs);
        }
        throw new PermanentAgentException("GLOBALSIGN_RESPONSE_INVALID",
                "GlobalSign trust chain response format is not recognized");
    }

    public void revokeCertificate(String serial, String reason) {
        // Atlas takes the reason as "revocation_reason".
        Map<String, Object> payload = Map.of("revocation_reason", mapRevocationReason(reason));
        sendWithBearerRetry("PATCH", "/certificates/" + serial, toJson(payload));
    }

    private AgentProperties.GlobalSignProperties cfg() {
        return properties.getGlobalsign();
    }

    private HttpResponse<String> sendWithBearerRetry(String method, String path, String body) {
        HttpResponse<String> response = sendAuthorized(method, path, body);
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            invalidateToken();
            response = sendAuthorized(method, path, body);
        }
        assert2xx(response, "GlobalSign API " + method + " " + path);
        return response;
    }

    private HttpResponse<String> sendAuthorized(String method, String path, String body) {
        HttpRequest.Builder req = HttpRequest.newBuilder(resolveUri(path))
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + getAccessToken())
                .header(HttpHeaders.ACCEPT, "application/json");
        if (body != null) {
            req.header(HttpHeaders.CONTENT_TYPE, JSON_CONTENT_TYPE);
        }
        HttpRequest request = switch (method.toUpperCase(Locale.ROOT)) {
            case "GET" -> req.GET().build();
            case "POST" -> req.POST(HttpRequest.BodyPublishers.ofString(body != null ? body : "")).build();
            case "PATCH" -> req.method("PATCH", HttpRequest.BodyPublishers.ofString(body != null ? body : "")).build();
            default -> throw new IllegalArgumentException("Unsupported method: " + method);
        };
        return send(request, "GlobalSign API call");
    }

    private String getAccessToken() {
        if (cachedToken != null && Instant.now().isBefore(tokenExpiresAt)) {
            return cachedToken;
        }
        synchronized (this) {
            if (cachedToken != null && Instant.now().isBefore(tokenExpiresAt)) {
                return cachedToken;
            }
            cachedToken = login();
            tokenExpiresAt = Instant.now().plusSeconds(Math.max(120, cfg().getTokenTtlSeconds() - 30));
            return cachedToken;
        }
    }

    private String login() {
        if (isBlank(cfg().getApiKey()) || isBlank(cfg().getApiSecret())) {
            throw new PermanentAgentException("GLOBALSIGN_CONFIG_MISSING",
                    "GlobalSign API credentials are missing. Set AGENT_GLOBALSIGN_API_KEY and AGENT_GLOBALSIGN_API_SECRET");
        }

        String body = toJson(Map.of("api_key", cfg().getApiKey(), "api_secret", cfg().getApiSecret()));
        HttpRequest request = HttpRequest.newBuilder(resolveUri(cfg().getLoginPath()))
            .header(HttpHeaders.CONTENT_TYPE, JSON_CONTENT_TYPE)
                .header(HttpHeaders.ACCEPT, "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = send(request, "GlobalSign login");
        assert2xx(response, "GlobalSign login");
        JsonNode json = parseJson(response.body());
        String token = json.path("access_token").asString(null);
        if (isBlank(token)) {
            throw new PermanentAgentException("GLOBALSIGN_AUTH_FAILED",
                    "GlobalSign login response did not include access_token");
        }
        return token;
    }

    private HttpResponse<String> send(HttpRequest request, String operation) {
        try {
            return getHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "CA_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("globalsign atlas " + operation, "globalsign-api", e);
            }
            throw new TransientAgentException("GLOBALSIGN_NETWORK_ERROR",
                    operation + " failed: " + e.getMessage(), e);
        }
    }

    private void assert2xx(HttpResponse<String> response, String operation) {
        int status = response.statusCode();
        if (status >= 200 && status < 300) {
            return;
        }
        String body = response.body() != null ? response.body() : "";
        // Treat 429/503 as upstream throttle — re-enqueue with Retry-After when supplied.
        if (status == 429 || status == 503) {
            Duration retryAfter = response.headers().firstValue("retry-after")
                    .flatMap(RateLimitClassifier::parseRetryAfterValueOpt)
                    .orElse(null);
            String msg = operation + " was rate-limited by GlobalSign (HTTP " + status + ")"
                    + (retryAfter == null ? " (no Retry-After supplied)"
                                          : " (Retry-After=" + retryAfter + ")")
                    + ": " + body;
            throw new RetryableAgentException("CA_PROVIDER_THROTTLED", msg, retryAfter);
        }
        if (status >= 500) {
            throw new TransientAgentException("GLOBALSIGN_SERVER_ERROR",
                    operation + " failed with status " + status + ": " + body);
        }
        throw new PermanentAgentException("GLOBALSIGN_API_ERROR",
                operation + " failed with status " + status + ": " + body);
    }

    private HttpClient getHttpClient() {
        if (httpClient != null) {
            return httpClient;
        }
        synchronized (this) {
            if (httpClient != null) {
                return httpClient;
            }
            HttpClient.Builder builder = HttpClient.newBuilder();
            SSLContext sslContext = buildMutualTlsContextIfPresent();
            if (sslContext != null) {
                builder.sslContext(sslContext);
            }
            httpClient = builder.build();
            return httpClient;
        }
    }

    private SSLContext buildMutualTlsContextIfPresent() {
        if (isBlank(cfg().getClientCertPemBase64()) || isBlank(cfg().getClientPrivateKeyPemBase64())) {
            return null;
        }
        try {
            String certPem = new String(Base64.getDecoder().decode(cfg().getClientCertPemBase64()), StandardCharsets.UTF_8);
            String keyPem = new String(Base64.getDecoder().decode(cfg().getClientPrivateKeyPemBase64()), StandardCharsets.UTF_8);

            List<X509Certificate> certChain = parseCertificates(certPem);
            if (certChain.isEmpty()) {
                throw new PermanentAgentException("GLOBALSIGN_MTLS_CONFIG_INVALID",
                        "No certificates found in AGENT_GLOBALSIGN_CLIENT_CERT_PEM_BASE64");
            }
            PrivateKey key = parsePrivateKey(keyPem);
            List<X509Certificate> orderedChain = orderChainLeafFirst(certChain);

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("globalsign-client", key, new char[0],
                    orderedChain.toArray(new java.security.cert.Certificate[0]));

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);
            return sslContext;
        } catch (Exception e) {
            throw new PermanentAgentException("GLOBALSIGN_MTLS_CONFIG_INVALID",
                    "Failed to build GlobalSign mTLS client certificate: " + e.getMessage(), e);
        }
    }

    private List<X509Certificate> parseCertificates(String pemChain) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection<? extends java.security.cert.Certificate> certs =
                cf.generateCertificates(new ByteArrayInputStream(pemChain.getBytes(StandardCharsets.UTF_8)));
        List<X509Certificate> out = new ArrayList<>();
        for (java.security.cert.Certificate cert : certs) {
            if (cert instanceof X509Certificate x509) {
                out.add(x509);
            }
        }
        return out;
    }

    private List<X509Certificate> orderChainLeafFirst(List<X509Certificate> certs) {
        X509Certificate leaf = certs.stream()
                .filter(c -> c.getBasicConstraints() < 0)
                .findFirst()
                .orElse(certs.get(0));

        List<X509Certificate> ordered = new ArrayList<>();
        ordered.add(leaf);
        for (X509Certificate cert : certs) {
            if (cert == leaf) {
                continue;
            }
            // Keep intermediates, drop self-signed roots from the client chain.
            if (isSelfSigned(cert)) {
                continue;
            }
            ordered.add(cert);
        }
        return ordered;
    }

    private boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }

    private PrivateKey parsePrivateKey(String pem) throws Exception {
        String normalized = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(normalized);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (Exception ignore) {
            return KeyFactory.getInstance("EC").generatePrivate(keySpec);
        }
    }

    private JsonNode parseJson(String raw) {
        try {
            return objectMapper.readTree(raw);
        } catch (JacksonException e) {
            throw new PermanentAgentException("GLOBALSIGN_RESPONSE_INVALID",
                    "Failed to parse GlobalSign JSON response: " + e.getMessage(), e);
        }
    }

    private URI resolveUri(String path) {
        String base = cfg().getApiBaseUrl();
        if (isBlank(base)) {
            throw new PermanentAgentException("GLOBALSIGN_CONFIG_MISSING",
                    "GlobalSign API base URL is not configured");
        }
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return URI.create(path);
        }
        String normalizedBase = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        return URI.create(normalizedBase + normalizedPath);
    }

    private String extractSerial(HttpResponse<String> response, JsonNode body) {
        String fromLocation = response.headers().firstValue("Location")
                .orElse(response.headers().firstValue("location").orElse(null));
        if (!isBlank(fromLocation)) {
            int idx = fromLocation.lastIndexOf('/');
            if (idx >= 0 && idx < fromLocation.length() - 1) {
                return fromLocation.substring(idx + 1);
            }
        }
        if (body.has("certificate")) {
            JsonNode n = body.get("certificate");
            if (n.isString()) {
                return n.asString();
            }
            if (n.has("serial_number")) {
                return n.path("serial_number").asString(null);
            }
            if (n.has("serial")) {
                return n.path("serial").asString(null);
            }
        }
        if (body.has("serial_number")) {
            return body.path("serial_number").asString(null);
        }
        if (body.has("serial")) {
            return body.path("serial").asString(null);
        }
        return null;
    }

    private String extractClaimId(HttpResponse<String> response, JsonNode body) {
        String fromLocation = response.headers().firstValue("Location")
                .orElse(response.headers().firstValue("location").orElse(null));
        if (!isBlank(fromLocation)) {
            int idx = fromLocation.lastIndexOf('/');
            if (idx >= 0 && idx < fromLocation.length() - 1) {
                return fromLocation.substring(idx + 1);
            }
        }
        if (body.has("id")) {
            return body.path("id").asString(null);
        }
        if (body.has("claim_id")) {
            return body.path("claim_id").asString(null);
        }
        return null;
    }

    private String encodePathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String mapRevocationReason(String reason) {
        if (isBlank(reason)) {
            return "unspecified";
        }
        return switch (reason.toUpperCase(Locale.ROOT)) {
            case "KEY_COMPROMISE" -> "keyCompromise";
            case "CESSATION_OF_OPERATION" -> "cessationOfOperation";
            case "AFFILIATION_CHANGED" -> "affiliationChanged";
            case "SUPERSEDED" -> "superseded";
            default -> "unspecified";
        };
    }

    private String toJson(Object o) {
        try {
            return objectMapper.writeValueAsString(o);
        } catch (JacksonException e) {
            throw new PermanentAgentException("GLOBALSIGN_REQUEST_INVALID",
                    "Failed to serialize GlobalSign request payload", e);
        }
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private void invalidateToken() {
        cachedToken = null;
        tokenExpiresAt = Instant.EPOCH;
    }

    public record IssueResult(String serial) {}

    public record DomainClaim(String claimId, String token, String domain) {}
}