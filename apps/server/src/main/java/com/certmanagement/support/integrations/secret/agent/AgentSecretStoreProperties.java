// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Config binding for the multi-provider agent secret store used by credJson materialization.
 *
 * <p>{@code certping.agent-secret-store.provider} selects which driver Spring instantiates. Only
 * that driver's subgroup needs to be populated — the others stay dormant and are never bound to
 * real bean state.
 */
@Data
@Component
@ConfigurationProperties(prefix = "certping.agent-secret-store")
public class AgentSecretStoreProperties {

    private AgentSecretStoreProvider provider = AgentSecretStoreProvider.AZURE_KV;

    private AzureKv azureKv = new AzureKv();
    private AwsSecretsManager awsSecretsManager = new AwsSecretsManager();
    private GcpSecretManager gcpSecretManager = new GcpSecretManager();
    private Local local = new Local();

    /**
     * Encrypted files in a directory shared with the bundled agent, for installs with no cloud
     * secret manager. Server and agent must use the same directory, key and prefix.
     */
    @Data
    public static class Local {
        private String directory = "/var/lib/certping/secrets";
        /** Base64 of 32 random bytes (AES-256); the same value as the agent's. */
        private String key;
        /** Prefix on secret names; ownership checks key off it. */
        private String ownPrefix = "certping-";
    }

    /** True only when the provider is set AND its selected driver's minimum config is present. */
    public boolean isConfigured() {
        return switch (provider) {
            case AZURE_KV -> azureKv.getVaultUri() != null && !azureKv.getVaultUri().isBlank();
            case AWS_SECRETS_MANAGER -> awsSecretsManager.getRegion() != null
                    && !awsSecretsManager.getRegion().isBlank();
            case GCP_SECRET_MANAGER -> gcpSecretManager.getProjectId() != null
                    && !gcpSecretManager.getProjectId().isBlank();
            case LOCAL -> local.getKey() != null && !local.getKey().isBlank();
        };
    }

    @Data
    public static class AzureKv {
        /** e.g. https://example-vault.vault.azure.net */
        private String vaultUri;
        /** KV emulator + sovereign-cloud edge cases only. Off in prod. */
        private boolean disableChallengeResourceVerification = false;
        /** Local-dev only — swaps DefaultAzureCredential for an emulator token. */
        private boolean useEmulatorCredential = false;
    }

    @Data
    public static class AwsSecretsManager {
        /** e.g. us-east-1 */
        private String region;
        /** Prefix stamped on names created here — ownership check keys off this. */
        private String ownStoreNamePrefix = "certping/";
        /** LocalStack override; unset in prod. */
        private String endpointOverride;
        /** {@code DeleteSecret} recovery window. AWS accepts 7–30. */
        private int recoveryWindowDays = 7;
        /** For WEB_IDENTITY_TOKEN auth mode. */
        private String roleArn;
        private String webIdentityTokenFile;
        private AwsAuthMode authMode = AwsAuthMode.DEFAULT;
    }

    @Data
    public static class GcpSecretManager {
        private String projectId;
        /**
         * Optional numeric project number of {@link #projectId}. Secret Manager returns resource names
         * with the project NUMBER, so the handles the agent persists ({@code version.getName()}) carry
         * it; set this so those handles are recognised as this store's.
         */
        private String projectNumber;
        /** Prefix on secret ids — ownership check keys off this. */
        private String ownStoreSecretPrefix = "certping-";
        private String credentialConfigFile;
        private String saJsonFile;
        private GcpAuthMode authMode = GcpAuthMode.ADC;
    }

    public enum AwsAuthMode {
        WEB_IDENTITY_TOKEN,
        INSTANCE_PROFILE,
        PROFILE,
        DEFAULT
    }

    public enum GcpAuthMode {
        WORKLOAD_IDENTITY_FEDERATION,
        ADC,
        SA_JSON
    }
}
