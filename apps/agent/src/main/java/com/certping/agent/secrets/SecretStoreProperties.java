// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "agent.secret-store")
public class SecretStoreProperties {

    private SecretStoreProvider provider = SecretStoreProvider.AZURE_KV;

    private AzureKvProperties azureKv = new AzureKvProperties();

    private AwsSecretsManagerProperties awsSecretsManager = new AwsSecretsManagerProperties();

    private GcpSecretManagerProperties gcpSecretManager = new GcpSecretManagerProperties();

    private LocalProperties local = new LocalProperties();

    /**
     * Encrypted files in a directory shared with the CertPing server, for installs with no cloud
     * secret manager. The server and the agent must use the same directory, key and prefix.
     */
    @Data
    public static class LocalProperties {
        private String directory = "/var/lib/certping/secrets";
        /** Base64 of 32 random bytes (AES-256). Same value as the server's. */
        private String key;
        /** Prefix on secret names; ownership checks key off it. */
        private String ownPrefix = "certping-";
    }

    @Data
    public static class AzureKvProperties {
        private String vaultUri;
        private AzureAuthMode authMode = AzureAuthMode.WORKLOAD_IDENTITY;
        private String tenantId;
        private String clientId;
        private String federatedTokenFile;
        private String clientSecret;
        private String clientCertificatePath;
        /** Required by the KV emulator and some sovereign-cloud edge cases. Off in prod. */
        private boolean disableChallengeResourceVerification;
    }

    @Data
    public static class AwsSecretsManagerProperties {
        private String region;
        /** Prefix stamped on created secrets — {@code isOwnedByThisAgent} keys off this. */
        private String ownStoreNamePrefix = "certping/";
        private AwsAuthMode authMode = AwsAuthMode.WEB_IDENTITY_TOKEN;
        private String roleArn;
        private String webIdentityTokenFile;
        /** LocalStack override; unset in prod. */
        private String endpointOverride;
        /** {@code DeleteSecret} recovery window. AWS accepts 7–30. */
        private int recoveryWindowDays = 7;
    }

    @Data
    public static class GcpSecretManagerProperties {
        private String projectId;
        /** Prefix on secret ids — {@code isOwnedByThisAgent} keys off this. */
        private String ownStoreSecretPrefix = "agent-";
        private GcpAuthMode authMode = GcpAuthMode.WORKLOAD_IDENTITY_FEDERATION;
        private String credentialConfigFile;
        private String saJsonFile;
    }

    public enum AzureAuthMode {
        WORKLOAD_IDENTITY,
        CLIENT_SECRET,
        CLIENT_CERTIFICATE,
        DEFAULT,
        EMULATOR
    }

    public enum AwsAuthMode {
        WEB_IDENTITY_TOKEN,
        INSTANCE_PROFILE,
        PROFILE,
        STATIC,
        DEFAULT
    }

    public enum GcpAuthMode {
        WORKLOAD_IDENTITY_FEDERATION,
        ADC,
        SA_JSON
    }
}
