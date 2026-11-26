// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.handler.acme;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.secrets.SecretStoreProvider;
import com.certping.agent.util.PemUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.exception.AcmeServerException;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AcmeAccountServiceTest {

    private static final String ORG = "0b9e2c8e-5d1f-4a57-9a1e-3c2f1d0e9b7a";
    private static final String STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";
    private static final String PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
    private static final String LEGACY_NAME = "acme-acct-" + ORG;
    private static final URL LOCATION = url("https://acme.example/acct/1");

    private FakeStore store;

    @BeforeEach
    void setUp() {
        store = new FakeStore();
    }

    // ── Secret naming ────────────────────────────────────────────────────────

    @Test
    void secretName_isOrgPlusTwelveHexOfDirectory_andFitsLocalStoreRules() {
        String name = AcmeAccountService.accountSecretName(ORG, STAGING);
        assertThat(name).startsWith("acme-acct-" + ORG + "-");
        assertThat(name.substring(name.length() - 12)).matches("[0-9a-f]{12}");
        assertThat(name).matches("^[A-Za-z0-9_-]{1,160}$");
    }

    @Test
    void secretName_differsPerDirectory_andIgnoresCosmeticUrlDifferences() {
        assertThat(AcmeAccountService.accountSecretName(ORG, STAGING))
                .isNotEqualTo(AcmeAccountService.accountSecretName(ORG, PRODUCTION));
        assertThat(AcmeAccountService.accountSecretName(ORG, " HTTPS://ACME-v02.api.letsencrypt.org:443/directory/ "))
                .isEqualTo(AcmeAccountService.accountSecretName(ORG, PRODUCTION));
    }

    // ── Per-directory accounts ───────────────────────────────────────────────

    @Test
    void twoDirectories_giveTwoAccounts() {
        try (var acme = new FakeAcme()) {
            AcmeAccountResult staging = service(STAGING).getOrCreate(ORG, null);
            AcmeAccountResult prod = service(PRODUCTION).getOrCreate(ORG, null);

            assertThat(staging.acmeAccountHandle()).isEqualTo(handle(AcmeAccountService.accountSecretName(ORG, STAGING)));
            assertThat(prod.acmeAccountHandle()).isEqualTo(handle(AcmeAccountService.accountSecretName(ORG, PRODUCTION)));
            assertThat(store.secrets).hasSize(2).doesNotContainKey(LEGACY_NAME);
            assertThat(store.secrets.get(AcmeAccountService.accountSecretName(ORG, STAGING)))
                    .isNotEqualTo(store.secrets.get(AcmeAccountService.accountSecretName(ORG, PRODUCTION)));
        }
    }

    @Test
    void switchingDirectory_createsNewAccountInsteadOfFailing() {
        try (var acme = new FakeAcme()) {
            String stagingHandle = service(STAGING).getOrCreate(ORG, null).acmeAccountHandle();
            String stagingPem = store.secrets.get(AcmeAccountService.accountSecretName(ORG, STAGING));

            // The server echoes the staging handle back after ACME_DIRECTORY_URL moved to production.
            AcmeAccountResult prod = service(PRODUCTION).getOrCreate(ORG, stagingHandle);

            assertThat(prod.acmeAccountHandle()).isNotEqualTo(stagingHandle)
                    .isEqualTo(handle(AcmeAccountService.accountSecretName(ORG, PRODUCTION)));
            assertThat(store.secrets.get(AcmeAccountService.accountSecretName(ORG, STAGING))).isEqualTo(stagingPem);

            // And back again: the staging account is found, not recreated.
            int before = store.creates.size();
            AcmeAccountResult again = service(STAGING).getOrCreate(ORG, prod.acmeAccountHandle());
            assertThat(again.acmeAccountHandle()).isEqualTo(stagingHandle);
            assertThat(store.creates).hasSize(before);
        }
    }

    @Test
    void suppliedHandleRegisteredOnDirectory_isUsedAsIs() {
        try (var acme = new FakeAcme()) {
            String h = service(STAGING).getOrCreate(ORG, null).acmeAccountHandle();
            int creates = store.creates.size();
            assertThat(service(STAGING).getOrCreate(ORG, h).acmeAccountHandle()).isEqualTo(h);
            assertThat(store.creates).hasSize(creates);
        }
    }

    // ── Legacy per-organization key ──────────────────────────────────────────

    @Test
    void legacyKey_registeredOnCurrentDirectory_migratesToScopedName() {
        String legacyPem = PemUtils.keyPairToPem(KeyPairUtils.createKeyPair(2048));
        store.secrets.put(LEGACY_NAME, legacyPem);
        try (var acme = new FakeAcme()) {
            acme.registered(STAGING, legacyPem);

            AcmeAccountResult r = service(STAGING).getOrCreate(ORG, handle(LEGACY_NAME));

            String scoped = AcmeAccountService.accountSecretName(ORG, STAGING);
            assertThat(r.acmeAccountHandle()).isEqualTo(handle(scoped));
            assertThat(store.secrets.get(scoped)).isEqualTo(legacyPem);
            assertThat(store.secrets.get(LEGACY_NAME)).isEqualTo(legacyPem);
            assertThat(store.deletes).isEmpty();
            assertThat(acme.registrations).isZero();

            // Second use reads the scoped name directly; no second copy.
            service(STAGING).getOrCreate(ORG, r.acmeAccountHandle());
            assertThat(store.creates).containsExactly(scoped);
        }
    }

    @Test
    void legacyKey_withNullHandle_alsoMigrates() {
        String legacyPem = PemUtils.keyPairToPem(KeyPairUtils.createKeyPair(2048));
        store.secrets.put(LEGACY_NAME, legacyPem);
        try (var acme = new FakeAcme()) {
            acme.registered(PRODUCTION, legacyPem);
            AcmeAccountResult r = service(PRODUCTION).getOrCreate(ORG, null);
            assertThat(store.secrets.get(AcmeAccountService.accountSecretName(ORG, PRODUCTION))).isEqualTo(legacyPem);
            assertThat(r.acmeAccountHandle()).isEqualTo(handle(AcmeAccountService.accountSecretName(ORG, PRODUCTION)));
        }
    }

    @Test
    void legacyKey_fromOtherDirectory_isKeptAndNewAccountCreated() {
        String legacyPem = PemUtils.keyPairToPem(KeyPairUtils.createKeyPair(2048));
        store.secrets.put(LEGACY_NAME, legacyPem);
        try (var acme = new FakeAcme()) {
            acme.registered(STAGING, legacyPem);

            AcmeAccountResult r = service(PRODUCTION).getOrCreate(ORG, handle(LEGACY_NAME));

            String scoped = AcmeAccountService.accountSecretName(ORG, PRODUCTION);
            assertThat(r.acmeAccountHandle()).isEqualTo(handle(scoped));
            assertThat(store.secrets.get(scoped)).isNotEqualTo(legacyPem);
            assertThat(store.secrets.get(LEGACY_NAME)).isEqualTo(legacyPem);
            assertThat(store.deletes).isEmpty();
            assertThat(acme.registrations).isEqualTo(1);
        }
    }

    @Test
    void scopedKeyStoredButNeverRegistered_isRegisteredNotReplaced() {
        String scoped = AcmeAccountService.accountSecretName(ORG, STAGING);
        String pem = PemUtils.keyPairToPem(KeyPairUtils.createKeyPair(2048));
        store.secrets.put(scoped, pem);
        try (var acme = new FakeAcme()) {
            AcmeAccountResult r = service(STAGING).getOrCreate(ORG, null);
            assertThat(r.acmeAccountHandle()).isEqualTo(handle(scoped));
            assertThat(store.secrets.get(scoped)).isEqualTo(pem);
            assertThat(store.creates).isEmpty();
            assertThat(acme.registrations).isEqualTo(1);
        }
    }

    @Test
    void foreignProviderHandle_fallsBackToScopedKey() {
        try (var acme = new FakeAcme()) {
            String h = service(STAGING).getOrCreate(ORG, null).acmeAccountHandle();
            store.invalidHandles.add("https://agent-kv.vault.azure.net/secrets/x");
            assertThat(service(STAGING).getOrCreate(ORG, "https://agent-kv.vault.azure.net/secrets/x")
                    .acmeAccountHandle()).isEqualTo(h);
        }
    }

    // ── Errors ───────────────────────────────────────────────────────────────

    @Test
    void nullOrBlankOrganizationId_throwsPermanent() {
        for (String org : new String[] {null, "  "}) {
            assertThatThrownBy(() -> service(STAGING).getOrCreate(org, "h"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ORGANIZATION_ID_MISSING"));
        }
    }

    @Test
    void lookup_networkError_isTransient() {
        String h = seedScoped(STAGING);
        try (var ignored = Mockito.mockConstruction(Session.class);
             var b = builderThrowing(new AcmeNetworkException(new IOException("unreachable")))) {
            assertThatThrownBy(() -> service(STAGING).getOrCreate(ORG, h))
                    .isInstanceOf(TransientAgentException.class)
                    .satisfies(e -> assertThat(((TransientAgentException) e).getErrorCode())
                            .isEqualTo("ACME_NETWORK_ERROR"));
        }
    }

    @Test
    void lookup_otherAcmeError_isLoadFailed() {
        String h = seedScoped(STAGING);
        try (var ignored = Mockito.mockConstruction(Session.class);
             var b = builderThrowing(new AcmeException("server broke"))) {
            assertThatThrownBy(() -> service(STAGING).getOrCreate(ORG, h))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ACCOUNT_LOAD_FAILED"));
        }
        assertThat(store.creates).isEmpty();
    }

    @Test
    void registration_errors_mapToTransientOrCreateFailed() {
        try (var ignored = Mockito.mockConstruction(Session.class);
             var b = builderThrowing(new AcmeNetworkException(new IOException("net")))) {
            assertThatThrownBy(() -> service(STAGING).getOrCreate(ORG, null))
                    .isInstanceOf(TransientAgentException.class);
        }
        // The key survived the failed registration and is reused on retry.
        assertThat(store.creates).hasSize(1);
        try (var ignored = Mockito.mockConstruction(Session.class);
             var b = builderThrowing(new AcmeException("rejected"))) {
            assertThatThrownBy(() -> service(STAGING).getOrCreate(ORG, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ACCOUNT_LOAD_FAILED"));
        }
        assertThat(store.creates).hasSize(1);
    }

    @Test
    void createNewAccount_acmeError_isCreateFailed() {
        AtomicBoolean only = new AtomicBoolean();
        try (var ignored = Mockito.mockConstruction(Session.class);
             MockedConstruction<AccountBuilder> b = Mockito.mockConstruction(AccountBuilder.class, (m, c) -> {
                 stubChain(m, only);
                 when(m.create(any(Session.class))).thenThrow(new AcmeException("rejected"));
             })) {
            assertThatThrownBy(() -> service(STAGING).getOrCreate(ORG, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_ACCOUNT_CREATE_FAILED"));
        }
    }

    // ── External account binding ────────────────────────────────────────────

    @Test
    void eabConfigured_bindsTheNewAccountWithTheTrimmedKeyIdAndHmacKey() {
        try (var ignored = Mockito.mockConstruction(Session.class);
             MockedConstruction<AccountBuilder> b = registeringBuilder()) {
            new AcmeAccountService(store, eabProps(" kid-1 ", "aGVsbG8\n")).getOrCreate(ORG, null);

            assertThat(b.constructed()).hasSize(1);
            verify(b.constructed().get(0)).withKeyIdentifier("kid-1", "aGVsbG8");
        }
    }

    @Test
    void noEab_registersWithoutBinding() {
        try (var ignored = Mockito.mockConstruction(Session.class);
             MockedConstruction<AccountBuilder> b = registeringBuilder()) {
            service(STAGING).getOrCreate(ORG, null);

            verify(b.constructed().get(0), never()).withKeyIdentifier(anyString(), anyString());
        }
    }

    @Test
    void noContactConfigured_registersWithoutAContact() {
        try (var ignored = Mockito.mockConstruction(Session.class);
             MockedConstruction<AccountBuilder> b = registeringBuilder()) {
            service(STAGING).getOrCreate(ORG, null);

            verify(b.constructed().get(0), never()).addContact(anyString());
        }
    }

    @Test
    void configuredContact_namesTheOrganization() {
        AgentProperties p = props(STAGING);
        p.getAcme().setAccountContact(" ops+{organizationId}@example.com ");
        try (var ignored = Mockito.mockConstruction(Session.class);
             MockedConstruction<AccountBuilder> b = registeringBuilder()) {
            new AcmeAccountService(store, p).getOrCreate(ORG, null);

            verify(b.constructed().get(0)).addContact("mailto:ops+" + ORG + "@example.com");
        }
    }

    @Test
    void eabKeyIdWithoutHmacKey_failsBeforeContactingTheCa() {
        try (var sessions = Mockito.mockConstruction(Session.class);
             MockedConstruction<AccountBuilder> b = registeringBuilder()) {
            assertThatThrownBy(() -> new AcmeAccountService(store, eabProps("kid-1", " ")).getOrCreate(ORG, null))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("ACME_EAB_INCOMPLETE"));
            assertThat(sessions.constructed()).isEmpty();
            assertThat(b.constructed()).isEmpty();
        }
    }

    @Test
    void existingAccount_isLookedUpWithoutBinding() {
        String pem = PemUtils.keyPairToPem(KeyPairUtils.createKeyPair(2048));
        store.secrets.put(AcmeAccountService.accountSecretName(ORG, STAGING), pem);
        try (var acme = new FakeAcme()) {
            acme.registered(STAGING, pem);
            new AcmeAccountService(store, eabProps("kid-1", "aGVsbG8")).getOrCreate(ORG, null);

            assertThat(acme.registrations).isZero();
            acme.builders.constructed().forEach(m -> verify(m, never()).withKeyIdentifier(anyString(), anyString()));
        }
    }

    @Test
    void unexpectedStoreReadError_propagatesWithoutCreating() {
        store.readError = new PermanentAgentException("KV_AUTH_FAILED", "bad creds");
        assertThatThrownBy(() -> service(STAGING).getOrCreate(ORG, null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KV_AUTH_FAILED"));
        assertThat(store.creates).isEmpty();
    }

    @Test
    void handleForThrowsUnexpected_propagates() {
        SecretStore broken = mock(SecretStore.class);
        when(broken.handleFor(anyString())).thenThrow(new IllegalStateException("driver not ready"));
        assertThatThrownBy(() -> new AcmeAccountService(broken, props(STAGING)).getOrCreate(ORG, null))
                .isInstanceOf(IllegalStateException.class);
        verify(broken, never()).read(anyString());
        verify(broken, never()).create(anyString(), anyString());
    }

    // ── PemUtils round-trip ──────────────────────────────────────────────────

    @Test
    void pemUtils_roundTrip_keyPairPreserved() {
        KeyPair original = KeyPairUtils.createKeyPair(2048);
        KeyPair restored = PemUtils.pemToKeyPair(PemUtils.keyPairToPem(original));
        assertThat(restored.getPrivate().getEncoded()).isEqualTo(original.getPrivate().getEncoded());
        assertThat(restored.getPublic().getEncoded()).isEqualTo(original.getPublic().getEncoded());
    }

    @Test
    void pemUtils_invalidPem_throwsPermanentException() {
        assertThatThrownBy(() -> PemUtils.pemToKeyPair("not-a-valid-pem"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("KEY_PAIR_PARSE_FAILED"));
    }

    // ── Account metadata (CA status report) ──────────────────────────────────

    @Test
    void newAccount_recordsUrlAndCreationTime_andDescribeReportsThemWithoutKey() {
        try (var acme = new FakeAcme()) {
            AcmeAccountService service = service(STAGING);
            long before = service.metadataVersion();
            service.getOrCreate(ORG, null);

            assertThat(service.metadataVersion()).isGreaterThan(before);
            String metaName = AcmeAccountService.metadataSecretName(ORG, STAGING);
            assertThat(store.metas.get(metaName)).contains("accountUrl").doesNotContain("PRIVATE KEY");

            AcmeAccountService.AccountDescription d = service(STAGING).describeAccount(ORG).orElseThrow();
            assertThat(d.organizationId()).isEqualTo(ORG);
            assertThat(d.accountUrl()).isEqualTo(LOCATION.toString());
            assertThat(d.keyType()).isEqualTo("RSA 2048");
            assertThat(d.createdAt()).isNotNull();
            assertThat(d.toString()).doesNotContain("PRIVATE KEY").doesNotContain("BEGIN");
        }
    }

    @Test
    void olderAccountWithoutMetadata_isDescribedWithNullUrlAndTime() {
        seedScoped(STAGING);
        AcmeAccountService.AccountDescription d = service(STAGING).describeAccount(ORG).orElseThrow();
        assertThat(d.accountUrl()).isNull();
        assertThat(d.createdAt()).isNull();
        assertThat(d.keyType()).isEqualTo("RSA 2048");
    }

    @Test
    void existingAccountLookedUp_recordsUrlButNoCreationTime_once() {
        String pem = PemUtils.keyPairToPem(KeyPairUtils.createKeyPair(2048));
        store.secrets.put(AcmeAccountService.accountSecretName(ORG, STAGING), pem);
        try (var acme = new FakeAcme()) {
            acme.registered(STAGING, pem);
            AcmeAccountService service = service(STAGING);
            service.getOrCreate(ORG, null);
            long after = service.metadataVersion();
            service.getOrCreate(ORG, null);
            assertThat(service.metadataVersion()).isEqualTo(after);
        }
        AcmeAccountService.AccountDescription d = service(STAGING).describeAccount(ORG).orElseThrow();
        assertThat(d.accountUrl()).isEqualTo(LOCATION.toString());
        assertThat(d.createdAt()).isNull();
    }

    @Test
    void noAccountOnThisDirectory_describesNothing() {
        seedScoped(PRODUCTION);
        assertThat(service(STAGING).describeAccount(ORG)).isEmpty();
        assertThat(service(STAGING).describeAccount(null)).isEmpty();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private AcmeAccountService service(String directory) {
        return new AcmeAccountService(store, props(directory));
    }

    private static AgentProperties props(String directory) {
        AgentProperties p = new AgentProperties();
        p.getAcme().setDirectoryUrl(directory);
        return p;
    }

    private static AgentProperties eabProps(String keyId, String hmacKey) {
        AgentProperties p = props(STAGING);
        p.getAcme().setEabKeyId(keyId);
        p.getAcme().setEabHmacKey(hmacKey);
        return p;
    }

    /** Builders whose create() registers a new account at LOCATION. */
    private static MockedConstruction<AccountBuilder> registeringBuilder() {
        return Mockito.mockConstruction(AccountBuilder.class, (m, c) -> {
            stubChain(m, new AtomicBoolean());
            Account account = mock(Account.class);
            when(account.getLocation()).thenReturn(LOCATION);
            when(m.create(any(Session.class))).thenReturn(account);
        });
    }

    private String seedScoped(String directory) {
        String name = AcmeAccountService.accountSecretName(ORG, directory);
        store.secrets.put(name, PemUtils.keyPairToPem(KeyPairUtils.createKeyPair(2048)));
        return handle(name);
    }

    private static String handle(String name) {
        return "local:" + name;
    }

    private static URL url(String s) {
        try {
            return URI.create(s).toURL();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void stubChain(AccountBuilder m, AtomicBoolean only) {
        when(m.onlyExisting()).thenAnswer(inv -> {
            only.set(true);
            return m;
        });
        when(m.agreeToTermsOfService()).thenReturn(m);
        when(m.useKeyPair(any())).thenReturn(m);
        when(m.addContact(anyString())).thenReturn(m);
    }

    private static MockedConstruction<AccountBuilder> builderThrowing(AcmeException e) {
        return Mockito.mockConstruction(AccountBuilder.class, (m, c) -> {
            stubChain(m, new AtomicBoolean());
            when(m.create(any(Session.class))).thenThrow(e);
        });
    }

    private static AcmeServerException accountDoesNotExist() {
        AcmeServerException e = mock(AcmeServerException.class);
        when(e.getType()).thenReturn(URI.create("urn:ietf:params:acme:error:accountDoesNotExist"));
        return e;
    }

    /** In-memory store with LOCAL-style handles ("local:" + name). */
    private static final class FakeStore implements SecretStore {
        final Map<String, String> secrets = new HashMap<>();
        final Map<String, String> metas = new HashMap<>();
        final List<String> creates = new ArrayList<>();
        final List<String> deletes = new ArrayList<>();
        final Set<String> invalidHandles = new HashSet<>();
        PermanentAgentException readError;

        @Override
        public String read(String handle) {
            if (readError != null) {
                throw readError;
            }
            if (invalidHandles.contains(handle) || !handle.startsWith("local:")) {
                throw new PermanentAgentException("SM_HANDLE_INVALID", handle);
            }
            String name = handle.substring("local:".length());
            String v = name.startsWith(AcmeAccountService.META_PREFIX) ? metas.get(name) : secrets.get(name);
            if (v == null) {
                throw new PermanentAgentException("LOCAL_SECRET_NOT_FOUND", handle);
            }
            return v;
        }

        @Override
        public String create(String name, String value) {
            assertThat(name).matches("^[A-Za-z0-9_-]{1,160}$");
            if (name.startsWith(AcmeAccountService.META_PREFIX)) {
                // Account metadata is kept apart so the key assertions above count keys only.
                metas.put(name, value);
                return handle(name);
            }
            creates.add(name);
            secrets.put(name, value);
            return handle(name);
        }

        @Override
        public String update(String handle, String value) {
            throw new AssertionError("ACME account keys are never updated");
        }

        @Override
        public void delete(String handle) {
            deletes.add(handle);
        }

        @Override
        public boolean isOwnedByThisAgent(String handle) {
            return true;
        }

        @Override
        public String handleFor(String name) {
            return handle(name);
        }

        @Override
        public SecretStoreProvider provider() {
            return null;
        }
    }

    /**
     * Fake ACME directories: tracks which public keys are registered on which directory
     * URL, keyed by the URL the Session was built with.
     */
    private static final class FakeAcme implements AutoCloseable {
        final Map<String, Set<String>> accounts = new HashMap<>();
        int registrations;
        private final MockedConstruction<Session> sessions;
        private final MockedConstruction<AccountBuilder> builders;
        private final Map<Session, String> sessionUrl = new HashMap<>();

        FakeAcme() {
            sessions = Mockito.mockConstruction(Session.class,
                    (s, ctx) -> sessionUrl.put(s, (String) ctx.arguments().get(0)));
            builders = Mockito.mockConstruction(AccountBuilder.class, (m, c) -> {
                AtomicBoolean only = new AtomicBoolean();
                KeyPair[] key = new KeyPair[1];
                when(m.onlyExisting()).thenAnswer(inv -> {
                    only.set(true);
                    return m;
                });
                when(m.agreeToTermsOfService()).thenReturn(m);
                when(m.addContact(anyString())).thenReturn(m);
                when(m.useKeyPair(any())).thenAnswer(inv -> {
                    key[0] = inv.getArgument(0);
                    return m;
                });
                when(m.create(any(Session.class))).thenAnswer(inv -> {
                    String dir = sessionUrl.get(inv.<Session>getArgument(0));
                    Set<String> keys = accounts.computeIfAbsent(dir, d -> new HashSet<>());
                    String id = fingerprint(key[0]);
                    if (only.get() && !keys.contains(id)) {
                        throw accountDoesNotExist();
                    }
                    if (!only.get()) {
                        registrations++;
                        keys.add(id);
                    }
                    Account a = mock(Account.class);
                    when(a.getLocation()).thenReturn(LOCATION);
                    return a;
                });
            });
        }

        void registered(String directory, String pem) {
            accounts.computeIfAbsent(directory, d -> new HashSet<>()).add(fingerprint(PemUtils.pemToKeyPair(pem)));
        }

        private static String fingerprint(KeyPair k) {
            return java.util.Base64.getEncoder().encodeToString(k.getPublic().getEncoded());
        }

        @Override
        public void close() {
            builders.close();
            sessions.close();
        }
    }
}
