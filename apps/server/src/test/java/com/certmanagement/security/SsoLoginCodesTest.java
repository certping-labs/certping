// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.controller.SsoExchangeController;
import com.certmanagement.dto.auth.AuthTokenResponse;
import com.certmanagement.exception.BadRequestException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class SsoLoginCodesTest {

    private static final ObjectMapper MAPPER = JsonMapper.builder().build();

    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final SsoLoginCodes codes;

    SsoLoginCodesTest() {
        when(redis.opsForValue()).thenReturn(values);
        codes = new SsoLoginCodes(redis, MAPPER);
    }

    private static AuthTokenResponse result() {
        return AuthTokenResponse.builder().accessToken("access-tok").refreshToken("refresh-tok").tokenType("Bearer")
                .expiresIn(3600L).userId(7).email("a@b.c").organizationId(1L).roles(Set.of("VIEWER")).build();
    }

    @Test
    void aCodeIs32RandomBytesHeldSixtySecondsAndItsValueIsTheSignInResult() {
        String code = codes.issue(result());

        assertThat(code).matches("[A-Za-z0-9_-]{43}");
        ArgumentCaptor<String> json = ArgumentCaptor.forClass(String.class);
        verify(values).set(eq("auth:sso-code:" + code), json.capture(), eq(Duration.ofSeconds(60)));
        assertThat(json.getValue()).contains("access-tok").contains("refresh-tok");
        assertThat(codes.issue(result())).isNotEqualTo(code);
    }

    @Test
    void redeemingTakesTheValueAtomicallySoACodeWorksOnce() {
        String code = "A".repeat(43);
        when(values.getAndDelete("auth:sso-code:" + code))
                .thenReturn(MAPPER.writeValueAsString(result()))
                .thenReturn(null);

        assertThat(codes.redeem(code)).get().extracting(AuthTokenResponse::getAccessToken).isEqualTo("access-tok");
        assertThat(codes.redeem(code)).isEmpty();
    }

    @Test
    void aMalformedCodeNeverReachesRedis() {
        assertThat(codes.redeem(null)).isEmpty();
        assertThat(codes.redeem("short")).isEmpty();
        assertThat(codes.redeem("A".repeat(42) + "*")).isEmpty();
        verify(values, org.mockito.Mockito.never()).getAndDelete(anyString());
    }

    @Test
    void theExchangeAnswersTheSignInResponseWithTheTokenUnderBothNames() {
        String code = "B".repeat(43);
        when(values.getAndDelete("auth:sso-code:" + code)).thenReturn(MAPPER.writeValueAsString(result()));
        SsoExchangeController controller = new SsoExchangeController(codes, MAPPER);

        Map<String, Object> body = controller.exchange(new SsoExchangeController.ExchangeRequest(code)).getBody();

        assertThat(body).containsEntry("accessToken", "access-tok").containsEntry("token", "access-tok")
                .containsEntry("refreshToken", "refresh-tok").containsEntry("tokenType", "Bearer")
                .containsEntry("userId", 7).containsKey("expiresIn");
    }

    @Test
    void anUnknownOrUsedCodeIsA400() {
        SsoExchangeController controller = new SsoExchangeController(codes, MAPPER);
        assertThatThrownBy(() -> controller.exchange(new SsoExchangeController.ExchangeRequest("C".repeat(43))))
                .isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> controller.exchange(null)).isInstanceOf(BadRequestException.class);
    }

    @Test
    void theExchangePathIsTheContractTheWebAppUses() {
        assertThat(SsoExchangeController.PATH).isEqualTo("/api/auth/sso/exchange");
        verifyNoInteractions(values);
    }
}
