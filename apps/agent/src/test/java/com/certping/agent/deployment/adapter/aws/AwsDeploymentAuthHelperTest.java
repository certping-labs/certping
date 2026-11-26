// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AwsDeploymentAuthHelperTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private static final String CTX = "TEST";

    // ---- parseCredential ----

    @Test
    void parseCredential_validJson_returnsParsedObject() {
        SimplePojo result = AwsDeploymentAuthHelper.parseCredential(
                objectMapper, "{\"value\":\"abc\"}", SimplePojo.class, CTX);
        assertThat(result.getValue()).isEqualTo("abc");
    }

    @Test
    void parseCredential_invalidJson_throwsPermanentCredentialInvalid() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.parseCredential(
                objectMapper, "not-valid-json", SimplePojo.class, CTX))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_CREDENTIAL_INVALID"));
    }

    // ---- requireField ----

    @Test
    void requireField_nonBlankValue_returnsValue() {
        assertThat(AwsDeploymentAuthHelper.requireField("hello", "myField", CTX)).isEqualTo("hello");
    }

    @Test
    void requireField_nullValue_throwsPermanent() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.requireField(null, "myField", CTX))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("myField");
    }

    @Test
    void requireField_blankValue_throwsPermanent() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.requireField("   ", "myField", CTX))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("myField");
    }

    // ---- requireRoleArn ----

    @Test
    void requireRoleArn_validArn_returnsArn() {
        String arn = "arn:aws:iam::123456789012:role/MyRole";
        assertThat(AwsDeploymentAuthHelper.requireRoleArn(arn, CTX)).isEqualTo(arn);
    }

    @Test
    void requireRoleArn_validArnWithSpecialChars_returnsArn() {
        String arn = "arn:aws:iam::123456789012:role/path/to/My-Role_Name+1";
        assertThatNoException().isThrownBy(() -> AwsDeploymentAuthHelper.requireRoleArn(arn, CTX));
    }

    @Test
    void requireRoleArn_blankArn_throwsPermanent() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.requireRoleArn("", CTX))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void requireRoleArn_invalidArnFormat_throwsPermanent() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.requireRoleArn("not-an-arn", CTX))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("roleArn");
    }

    @Test
    void requireRoleArn_wrongAccountIdLength_throwsPermanent() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.requireRoleArn(
                "arn:aws:iam::12345:role/MyRole", CTX))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ---- requireRegion ----

    @Test
    void requireRegion_validRegion_returnsRegion() {
        assertThat(AwsDeploymentAuthHelper.requireRegion("us-east-1", CTX)).isEqualTo("us-east-1");
    }

    @Test
    void requireRegion_validApacRegion_returnsRegion() {
        assertThatNoException().isThrownBy(() -> AwsDeploymentAuthHelper.requireRegion("ap-southeast-2", CTX));
    }

    @Test
    void requireRegion_blankRegion_throwsPermanent() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.requireRegion("", CTX))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void requireRegion_invalidRegionFormat_throwsPermanent() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.requireRegion("not-a-region!", CTX))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("region");
    }

    @Test
    void requireRegion_uppercaseRegion_throwsPermanent() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.requireRegion("US-EAST-1", CTX))
                .isInstanceOf(PermanentAgentException.class);
    }

    // ---- validateRoleArn / validateRegion (already exercised above, but separate dispatch coverage) ----

    @Test
    void validateRoleArn_validArn_doesNotThrow() {
        assertThatNoException().isThrownBy(() -> AwsDeploymentAuthHelper.validateRoleArn(
                "arn:aws:iam::123456789012:role/MyRole", CTX));
    }

    @Test
    void validateRoleArn_invalidFormat_throws() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.validateRoleArn("garbage", CTX))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void validateRegion_validRegion_doesNotThrow() {
        assertThatNoException().isThrownBy(() -> AwsDeploymentAuthHelper.validateRegion("eu-west-3", CTX));
    }

    @Test
    void validateRegion_invalidFormat_throws() {
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.validateRegion("garbage", CTX))
                .isInstanceOf(PermanentAgentException.class);
    }

    // POJO for parseCredential test
    public static class SimplePojo {
        private String value;
        public String getValue() { return value; }
        public void setValue(String value) { this.value = value; }
    }

    private static final String ARN = "arn:aws:iam::123456789012:role/MyRole";

    @Test
    void assumeRole_delegatesToService() {
        AwsAssumeRoleService svc = mock(AwsAssumeRoleService.class);
        AwsSessionCredentials creds = AwsSessionCredentials.create("AK", "SK", "TK");
        when(svc.assumeRole(ARN, "us-east-1", "akid", "secret")).thenReturn(creds);

        AwsSessionCredentials out = AwsDeploymentAuthHelper.assumeRole(svc, ARN, "us-east-1", "akid", "secret");
        assertThat(out).isSameAs(creds);
        verify(svc).assumeRole(ARN, "us-east-1", "akid", "secret");
    }

    @Test
    void buildAuthContext_returnsContextWithValidatedFields() {
        AwsAssumeRoleService svc = mock(AwsAssumeRoleService.class);
        AwsSessionCredentials creds = AwsSessionCredentials.create("AK", "SK", "TK");
        when(svc.assumeRoleValidated(ARN, "us-east-1", "akid", "secret")).thenReturn(creds);

        AwsDeploymentAuthHelper.AwsAuthContext ctx = AwsDeploymentAuthHelper.buildAuthContext(
                svc, ARN, "us-east-1", "akid", "secret", CTX);

        assertThat(ctx.roleArn()).isEqualTo(ARN);
        assertThat(ctx.region()).isEqualTo("us-east-1");
        assertThat(ctx.sessionCredentials()).isSameAs(creds);
    }

    @Test
    void buildAuthContext_invalidRoleArn_throwsPermanent() {
        AwsAssumeRoleService svc = mock(AwsAssumeRoleService.class);
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.buildAuthContext(
                svc, "bad", "us-east-1", "akid", "secret", CTX))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void buildAuthContext_invalidRegion_throwsPermanent() {
        AwsAssumeRoleService svc = mock(AwsAssumeRoleService.class);
        assertThatThrownBy(() -> AwsDeploymentAuthHelper.buildAuthContext(
                svc, ARN, "BAD", "akid", "secret", CTX))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void awsAuthContext_record_accessors() {
        AwsSessionCredentials creds = AwsSessionCredentials.create("AK", "SK", "TK");
        AwsDeploymentAuthHelper.AwsAuthContext ctx =
                new AwsDeploymentAuthHelper.AwsAuthContext(ARN, "us-east-1", creds);
        assertThat(ctx.roleArn()).isEqualTo(ARN);
        assertThat(ctx.region()).isEqualTo("us-east-1");
        assertThat(ctx.sessionCredentials()).isSameAs(creds);
    }
}
