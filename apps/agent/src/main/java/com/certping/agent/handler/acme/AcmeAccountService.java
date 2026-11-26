// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.handler.acme;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.util.PemUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Manages the ACME account key for an organization on one ACME directory.
 *
 * An ACME account only exists on the directory that registered it, so the key is
 * stored per organization AND directory, under
 * "acme-acct-{organizationId}-{first 12 hex of sha256(normalized directory URL)}".
 * Switching ACME_DIRECTORY_URL (for example Let's Encrypt staging to production)
 * therefore gets its own account instead of failing to load the other directory's.
 *
 * Lookup order:
 *   1. the handle the server sent (the last account used for this organization),
 *      if its key is registered on the configured directory
 *   2. the directory-scoped key; if present but not registered yet (an earlier
 *      registration failed after the key was stored), it is registered now
 *   3. the legacy per-organization key "acme-acct-{organizationId}" from older
 *      agents: it records no directory, so it is treated as belonging to the
 *      configured directory and, if that directory knows it, copied to the scoped
 *      name. The legacy secret is never modified or deleted.
 *   4. otherwise a new key is generated, stored under the scoped name, and registered.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AcmeAccountService {

    static final String NAME_PREFIX = "acme-acct-";
    private static final String ACCOUNT_DOES_NOT_EXIST = "urn:ietf:params:acme:error:accountDoesNotExist";
    static final String NOT_IN_DIRECTORY = "ACME_ACCOUNT_NOT_IN_DIRECTORY";

    /** Metadata next to an account key: its account URL and creation time, never the key. */
    static final String META_PREFIX = "acme-meta-";

    private final SecretStore secretStore;
    private final AgentProperties properties;

    /** Metadata secrets known to exist, so a renewal does not read them again. */
    private final Set<String> recordedMetadata = ConcurrentHashMap.newKeySet();
    /** Bumped whenever account metadata is written; the CA status report rebuilds when it changes. */
    private final AtomicLong metadataVersion = new AtomicLong();

    /** What the agent can say about one stored ACME account. Holds no key material. */
    public record AccountDescription(String organizationId, String accountUrl, String keyType, Instant createdAt) {
    }

    public long metadataVersion() {
        return metadataVersion.get();
    }

    /**
     * The organization's account on the configured directory, if its key is in this agent's secret
     * store. Reads the key only to name its type; the key itself never leaves this method.
     */
    public Optional<AccountDescription> describeAccount(String organizationId) {
        if (organizationId == null || organizationId.isBlank()) {
            return Optional.empty();
        }
        String directoryUrl = properties.getAcme().getDirectoryUrl();
        if (directoryUrl == null || directoryUrl.isBlank()) {
            return Optional.empty();
        }
        String pem = readPemOrNull(secretStore.handleFor(accountSecretName(organizationId, directoryUrl)));
        if (pem == null) {
            return Optional.empty();
        }
        String keyType = keyTypeOf(PemUtils.pemToKeyPair(pem));
        Properties meta = readMetadata(metadataSecretName(organizationId, directoryUrl));
        String accountUrl = meta == null ? null : blankToNull(meta.getProperty("accountUrl"));
        Instant createdAt = null;
        if (meta != null && blankToNull(meta.getProperty("createdAt")) != null) {
            try {
                createdAt = Instant.parse(meta.getProperty("createdAt").trim());
            } catch (RuntimeException ignored) {
                // Unreadable time: reported as unknown.
            }
        }
        return Optional.of(new AccountDescription(organizationId, accountUrl, keyType, createdAt));
    }

    static String metadataSecretName(String organizationId, String directoryUrl) {
        return META_PREFIX + organizationId + "-" + directoryHash(directoryUrl);
    }

    /** "RSA 2048" or "EC 256": the algorithm and size, read from the public half. */
    static String keyTypeOf(KeyPair keyPair) {
        PublicKey key = keyPair == null ? null : keyPair.getPublic();
        if (key instanceof RSAPublicKey rsa) {
            return "RSA " + rsa.getModulus().bitLength();
        }
        if (key instanceof ECPublicKey ec) {
            return "EC " + ec.getParams().getOrder().bitLength();
        }
        return key == null ? null : key.getAlgorithm();
    }

    /**
     * Stores the account URL (and, for a new account, the creation time) beside the key, once. A
     * failure here never fails the order: the report then shows the account without them.
     */
    private void recordMetadata(String organizationId, URL accountUrl, Instant createdAt) {
        String directoryUrl = properties.getAcme().getDirectoryUrl();
        if (accountUrl == null || directoryUrl == null || directoryUrl.isBlank()) {
            return;
        }
        String name = metadataSecretName(organizationId, directoryUrl);
        if (recordedMetadata.contains(name)) {
            return;
        }
        try {
            if (readMetadata(name) == null) {
                Properties meta = new Properties();
                meta.setProperty("accountUrl", accountUrl.toString());
                if (createdAt != null) {
                    meta.setProperty("createdAt", createdAt.toString());
                }
                StringWriter out = new StringWriter();
                meta.store(out, null);
                secretStore.create(name, out.toString());
                metadataVersion.incrementAndGet();
            }
            recordedMetadata.add(name);
        } catch (Exception e) {
            log.warn("Could not record ACME account metadata for organization {}: {}", organizationId, e.getMessage());
        }
    }

    private Properties readMetadata(String name) {
        String raw = readPemOrNull(secretStore.handleFor(name));
        if (raw == null) {
            return null;
        }
        Properties meta = new Properties();
        try {
            meta.load(new StringReader(raw));
        } catch (IOException e) {
            return null;
        }
        return meta;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    public AcmeAccountResult getOrCreate(String organizationId, String acmeAccountHandle) {
        if (organizationId == null || organizationId.isBlank()) {
            throw new PermanentAgentException("ORGANIZATION_ID_MISSING", "organizationId is null or blank");
        }
        String directoryUrl = properties.getAcme().getDirectoryUrl();
        String scopedName = accountSecretName(organizationId, directoryUrl);
        String legacyHandle = secretStore.handleFor(NAME_PREFIX + organizationId);

        // 1. The handle the server sent. Unusable (foreign provider, missing secret) or not
        //    registered on this directory: fall through instead of failing the order.
        //    The legacy handle is left to step 3 so it gets migrated.
        boolean suppliedHandle = acmeAccountHandle != null && !acmeAccountHandle.isBlank()
                && !acmeAccountHandle.equals(legacyHandle);
        if (suppliedHandle) {
            try {
                return loadExistingAccount(organizationId, acmeAccountHandle);
            } catch (PermanentAgentException e) {
                if (!isNoAccountAtHandle(e) && !NOT_IN_DIRECTORY.equals(e.getErrorCode())) {
                    throw e;
                }
                log.debug("Provided ACME handle unusable on {} ({}); trying the directory-scoped key",
                        directoryUrl, e.getErrorCode());
            }
        }

        // 2. Directory-scoped key.
        String scopedHandle = secretStore.handleFor(scopedName);
        KeyPair scopedKey = readKeyOrNull(scopedHandle);
        if (scopedKey != null) {
            try {
                return lookUp(organizationId, scopedKey, scopedHandle);
            } catch (PermanentAgentException e) {
                if (!NOT_IN_DIRECTORY.equals(e.getErrorCode())) {
                    throw e;
                }
                return register(organizationId, scopedKey, scopedHandle);
            }
        }

        // 3. Legacy per-organization key: migrate when the configured directory knows it.
        String legacyPem = readPemOrNull(legacyHandle);
        if (legacyPem != null) {
            try {
                AcmeAccountResult legacy = lookUp(organizationId, PemUtils.pemToKeyPair(legacyPem), legacyHandle);
                String migrated = secretStore.create(scopedName, legacyPem);
                log.info("Migrated legacy ACME account key for organization {} to {}", organizationId, migrated);
                return new AcmeAccountResult(legacy.keyPair(), legacy.accountLocation(), migrated);
            } catch (PermanentAgentException e) {
                if (!NOT_IN_DIRECTORY.equals(e.getErrorCode())) {
                    throw e;
                }
                log.info("Legacy ACME account key for organization {} is not registered on {}; "
                        + "keeping it and creating a new account", organizationId, directoryUrl);
            }
        }

        // 4. Truly first issuance for this organization on this directory.
        return createNewAccount(organizationId, scopedName);
    }

    /**
     * Secret name for an organization's account on one ACME directory. Only
     * [a-f0-9-] characters are added, so it fits every store's name rules.
     */
    static String accountSecretName(String organizationId, String directoryUrl) {
        return NAME_PREFIX + organizationId + "-" + directoryHash(directoryUrl);
    }

    static String directoryHash(String directoryUrl) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(normalizeDirectoryUrl(directoryUrl).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 12);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Trims, lowercases scheme and host, drops a default port and trailing slashes. */
    static String normalizeDirectoryUrl(String directoryUrl) {
        String raw = directoryUrl == null ? "" : directoryUrl.trim();
        try {
            URI uri = URI.create(raw);
            if (uri.getScheme() != null && uri.getHost() != null) {
                String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
                int port = uri.getPort();
                boolean defaultPort = port == -1
                        || ("https".equals(scheme) && port == 443)
                        || ("http".equals(scheme) && port == 80);
                String path = uri.getRawPath() == null ? "" : uri.getRawPath();
                String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
                raw = scheme + "://" + uri.getHost().toLowerCase(Locale.ROOT)
                        + (defaultPort ? "" : ":" + port) + path + query;
            }
        } catch (IllegalArgumentException ignored) {
            // Not a URI: hash the trimmed text as is.
        }
        while (raw.endsWith("/")) {
            raw = raw.substring(0, raw.length() - 1);
        }
        return raw;
    }

    // ── Private ──────────────────────────────────────────────────────────────

    /**
     * Recognises "no ACME account at this handle" across all provider drivers:
     * secret-not-found (any provider), and handle-unparseable variants that occur
     * when a foreign-provider handle survives a provider switch (Azure, AWS, GCP).
     */
    private static boolean isNoAccountAtHandle(PermanentAgentException e) {
        String code = e.getErrorCode();
        if (code == null) {
            return false;
        }
        return code.endsWith("_SECRET_NOT_FOUND")
                || "SM_HANDLE_INVALID".equals(code)
                || "SM_HANDLE_BLANK".equals(code)
                || "KV_URI_INVALID".equals(code)
                || "KV_URI_BLANK".equals(code);
    }

    private String readPemOrNull(String handle) {
        try {
            return secretStore.read(handle);
        } catch (PermanentAgentException e) {
            if (isNoAccountAtHandle(e)) {
                return null;
            }
            throw e;
        }
    }

    private KeyPair readKeyOrNull(String handle) {
        String pem = readPemOrNull(handle);
        return pem == null ? null : PemUtils.pemToKeyPair(pem);
    }

    private AcmeAccountResult createNewAccount(String organizationId, String secretName) {
        log.info("No ACME account found for organization {} on {}, creating a new account",
                organizationId, properties.getAcme().getDirectoryUrl());
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048);
        // Persist the key material first so a transient ACME failure doesn't lose the generated key;
        // the next attempt finds it under the scoped name and registers it.
        String storedPath = secretStore.create(secretName, PemUtils.keyPairToPem(keyPair));
        return register(organizationId, keyPair, storedPath);
    }

    private AcmeAccountResult register(String organizationId, KeyPair keyPair, String handle) {
        String eabKeyId = blankToNull(properties.getAcme().getEabKeyId());
        String eabHmacKey = blankToNull(properties.getAcme().getEabHmacKey());
        if ((eabKeyId == null) != (eabHmacKey == null)) {
            throw new PermanentAgentException("ACME_EAB_INCOMPLETE",
                    "External account binding needs both ACME_EAB_KEY_ID and ACME_EAB_HMAC_KEY; only one is set");
        }
        try {
            Session session = new Session(properties.getAcme().getDirectoryUrl());
            AccountBuilder builder = new AccountBuilder()
                    .agreeToTermsOfService()
                    .useKeyPair(keyPair);
            String contact = properties.getAcme().getAccountContact();
            if (contact != null && !contact.isBlank()) {
                builder.addContact("mailto:" + contact.trim().replace("{organizationId}", organizationId));
            }
            if (eabKeyId != null) {
                builder.withKeyIdentifier(eabKeyId, eabHmacKey);
            }
            Account account = builder.create(session);

            log.info("ACME account created for organization {}, key stored at {}", organizationId, handle);
            recordMetadata(organizationId, account.getLocation(), Instant.now());
            return new AcmeAccountResult(keyPair, account.getLocation(), handle);

        } catch (AcmeNetworkException e) {
            throw new TransientAgentException("ACME_NETWORK_ERROR",
                    "Network error creating ACME account: " + e.getMessage(), e);
        } catch (AcmeException e) {
            throw new PermanentAgentException("ACME_ACCOUNT_CREATE_FAILED",
                    "Failed to create ACME account for organization " + organizationId + ": " + e.getMessage(), e);
        }
    }

    private AcmeAccountResult loadExistingAccount(String organizationId, String acmeAccountHandle) {
        log.info("Loading existing ACME account for organization {} from {}", organizationId, acmeAccountHandle);
        String pem = secretStore.read(acmeAccountHandle);
        return lookUp(organizationId, PemUtils.pemToKeyPair(pem), acmeAccountHandle);
    }

    /** Finds the account for this key on the configured directory, without registering it. */
    private AcmeAccountResult lookUp(String organizationId, KeyPair keyPair, String handle) {
        try {
            Session session = new Session(properties.getAcme().getDirectoryUrl());
            // onlyExisting() looks the account up by key pair; no account URL storage needed.
            Account account = new AccountBuilder()
                    .onlyExisting()
                    .useKeyPair(keyPair)
                    .create(session);

            log.info("Loaded ACME account for organization {}, location {}", organizationId, account.getLocation());
            recordMetadata(organizationId, account.getLocation(), null);
            return new AcmeAccountResult(keyPair, account.getLocation(), handle);

        } catch (AcmeNetworkException e) {
            throw new TransientAgentException("ACME_NETWORK_ERROR",
                    "Network error loading ACME account: " + e.getMessage(), e);
        } catch (AcmeServerException e) {
            if (e.getType() != null && ACCOUNT_DOES_NOT_EXIST.equals(e.getType().toString())) {
                throw new PermanentAgentException(NOT_IN_DIRECTORY,
                        "ACME key at " + handle + " has no account on " + properties.getAcme().getDirectoryUrl(), e);
            }
            throw loadFailed(handle, e);
        } catch (AcmeException e) {
            throw loadFailed(handle, e);
        }
    }

    private static PermanentAgentException loadFailed(String handle, AcmeException e) {
        return new PermanentAgentException("ACME_ACCOUNT_LOAD_FAILED",
                "Failed to load ACME account from " + handle + ": " + e.getMessage(), e);
    }
}
