// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent.aws;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretGoneException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AwsSecretsManagerAgentDriverTest {

    private AwsSecretsManagerAgentDriver driverWithFakeAccount() throws Exception {
        AgentSecretStoreProperties props = new AgentSecretStoreProperties();
        props.getAwsSecretsManager().setRegion("us-east-1");
        props.getAwsSecretsManager().setOwnStoreNamePrefix("certping/");
        AwsSecretsManagerAgentDriver d = new AwsSecretsManagerAgentDriver(props);
        // Bypass init() (which does STS lookup). Set private fields directly for pure-logic tests.
        setField(d, "ownRegion", "us-east-1");
        setField(d, "ownAccountId", "123456789012");
        setField(d, "ownNamePrefix", "certping/");
        return d;
    }

    @Test
    void provider_returnsAws() throws Exception {
        assertThat(driverWithFakeAccount().provider()).isEqualTo(AgentSecretStoreProvider.AWS_SECRETS_MANAGER);
    }

    @Test
    void handleFor_producesExpectedArn() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        assertThat(d.handleFor("team-a/cred-1"))
                .isEqualTo("arn:aws:secretsmanager:us-east-1:123456789012:secret:certping/team-a/cred-1");
    }

    @Test
    void handleFor_rejectsInvalidName() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        assertThatThrownBy(() -> d.handleFor("has spaces"))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void isOwnedByThisCertManager_trueForOwnArn() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        assertThat(d.isOwnedByThisCertManager(
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:certping/team-a/x-Ab1234"))
                .isTrue();
    }

    @Test
    void isOwnedByThisCertManager_falseForForeignAccount() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        assertThat(d.isOwnedByThisCertManager(
                "arn:aws:secretsmanager:us-east-1:999999999999:secret:certping/foo-Ab1234"))
                .isFalse();
    }

    @Test
    void isOwnedByThisCertManager_falseForDifferentPrefix() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        assertThat(d.isOwnedByThisCertManager(
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:someone-else/foo-Ab1234"))
                .isFalse();
    }

    @Test
    void isOwnedByThisCertManager_falseForNullOrMalformed() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        assertThat(d.isOwnedByThisCertManager(null)).isFalse();
        assertThat(d.isOwnedByThisCertManager("not-an-arn")).isFalse();
    }

    @Test
    void deleteIfOwned_noopForBlankOrForeign() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        d.deleteIfOwned(null);
        d.deleteIfOwned("");
        d.deleteIfOwned("arn:aws:secretsmanager:us-east-1:999999999999:secret:foreign/x");
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target, value);
    }

    @Test
    void isAgentCertificateHandle_acceptsOnlyTheCertsOwnSecret() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        String arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:";

        assertThat(d.isAgentCertificateHandle(arn + "certping/cert-123-AbC123", "cert-123")).isTrue();
        assertThat(d.isAgentCertificateHandle(arn + "certping/cert-123", "cert-123")).isTrue();
        assertThat(d.isAgentCertificateHandle(arn + "certping/certping-org7-cred-1-AbC123", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(
                "arn:aws:secretsmanager:us-east-1:111111111111:secret:certping/cert-123-AbC123", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle(arn + "other/cert-123-AbC123", "cert-123")).isFalse();
        assertThat(d.isAgentCertificateHandle("not-an-arn", "cert-123")).isFalse();
    }

    @Test
    void read_secretMarkedForDeletion_isGone_otherRefusalsAreNot() throws Exception {
        AwsSecretsManagerAgentDriver d = driverWithFakeAccount();
        SecretsManagerClient client = mock(SecretsManagerClient.class);
        setField(d, "client", client);
        String handle = "arn:aws:secretsmanager:us-east-1:123456789012:secret:certping/cert-123-AbC123";
        when(client.getSecretValue(any(GetSecretValueRequest.class)))
                .thenThrow(InvalidRequestException.builder().message("You can't perform this operation on the "
                        + "secret because it was marked for deletion.").build())
                .thenThrow(InvalidRequestException.builder().message("Something else is invalid.").build())
                .thenThrow(SecretsManagerException.builder().message("User is not authorized").statusCode(403).build());

        assertThatThrownBy(() -> d.read(handle)).isInstanceOf(AgentSecretGoneException.class);
        assertThatThrownBy(() -> d.read(handle)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> d.read(handle)).isInstanceOf(IllegalStateException.class);
    }
}
