// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.platform.DeviceSourceProfile;
import com.certping.agent.platform.DeviceSourceProfileRegistry;
import com.certping.agent.scep.ca.NoopScepCaBackend;
import com.certping.agent.scep.intune.NoopIntuneScepValidator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.security.Security;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

class ScepControllerTest {

    private MockMvc mvc;

    @BeforeAll
    static void provider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() {
        AgentProperties props = new AgentProperties();
        props.setOrganizationId("42");
        NoopScepCaBackend backend = new NoopScepCaBackend();
        // One Intune source: /scep/v1/intune-primary plus the /scep/v1/default compatibility alias.
        DeviceSourceProfileRegistry sources = Mockito.mock(DeviceSourceProfileRegistry.class);
        Mockito.when(sources.all()).thenReturn(List.of(new DeviceSourceProfile(
                "intune-primary", DevicePlatformType.INTUNE, "ENDPOINT_MANAGEMENT",
                "Test Intune", null, Map.of())));
        ScepEndpointRegistry registry = new ScepEndpointRegistry(props, backend, sources);
        registry.bootstrap();
        ScepService service = new ScepService(registry, new PkiMessageCodec(),
                new NoopIntuneScepValidator(), new ScepTransactionStore(props),
                Mockito.mock(AgentMessageSender.class), Clock.systemUTC(), ScepProfileHintResolver.NONE);

        mvc = MockMvcBuilders.standaloneSetup(new ScepController(service))
                .setControllerAdvice(new ScepExceptionAdvice())
                .build();
    }

    @Test
    void getCaCapsReturnsTextList() throws Exception {
        mvc.perform(get("/scep/v1/intune-primary").param("operation", "GetCACaps"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("POSTPKIOperation")));
    }

    @Test
    void defaultCompatibilityAliasServesTheSingleIntuneSource() throws Exception {
        mvc.perform(get("/scep/v1/default").param("operation", "GetCACaps"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("POSTPKIOperation")));
    }

    @Test
    void answersAtThePkiclientExePathWindowsClientsAppend() throws Exception {
        // Windows/NDES clients request /scep/v1/{id}/pkiclient.exe?operation=... — must not 404.
        mvc.perform(get("/scep/v1/intune-primary/pkiclient.exe").param("operation", "GetCACaps"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("POSTPKIOperation")));
    }

    @Test
    void getCaCertReturnsPkcs7() throws Exception {
        mvc.perform(get("/scep/v1/intune-primary").param("operation", "GetCACert"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(ScepConstants.CT_CA_RA_CERT));
    }

    @Test
    void unknownOperationIsBadRequest() throws Exception {
        mvc.perform(get("/scep/v1/intune-primary").param("operation", "Nonsense"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void getNextCaCertNotAdvertisedIsBadRequest() throws Exception {
        mvc.perform(get("/scep/v1/intune-primary").param("operation", "GetNextCACert"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unresolvableEndpointIsBadRequest() throws Exception {
        mvc.perform(get("/scep/v1/nope").param("operation", "GetCACaps"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void pkiOperationPostWithGarbageIsBadRequest() throws Exception {
        mvc.perform(post("/scep/v1/intune-primary").param("operation", "PKIOperation")
                        .contentType(ScepConstants.CT_PKI_MESSAGE).content(new byte[]{1, 2, 3, 4}))
                .andExpect(status().isBadRequest());
    }

    @Test
    void pkiOperationPostAcceptsAnyOrNoContentType() throws Exception {
        ScepService service = Mockito.mock(ScepService.class);
        Mockito.when(service.pkiOperation("intune-primary", new byte[]{7, 8}))
                .thenReturn(new BinaryResponse(ScepConstants.CT_PKI_MESSAGE, new byte[]{1}));
        MockMvc mockedMvc = MockMvcBuilders.standaloneSetup(new ScepController(service)).build();

        mockedMvc.perform(post("/scep/v1/intune-primary").param("operation", "PKIOperation")
                        .content(new byte[]{7, 8}))
                .andExpect(status().isOk())
                .andExpect(content().contentType(ScepConstants.CT_PKI_MESSAGE));
        mockedMvc.perform(post("/scep/v1/intune-primary").param("operation", "PKIOperation")
                        .contentType("application/octet-stream").content(new byte[]{7, 8}))
                .andExpect(status().isOk());
    }

    @Test
    void pkiOperationGetWithGarbageIsBadRequest() throws Exception {
        String message = Base64.getEncoder().encodeToString(new byte[]{9, 9, 9});
        mvc.perform(get("/scep/v1/intune-primary")
                        .param("operation", "PKIOperation").param("message", message))
                .andExpect(status().isBadRequest());
    }

    @Test
    void transactionReuseWithDifferentCsrIsConflict() throws Exception {
        ScepService conflictingService = Mockito.mock(ScepService.class);
        Mockito.when(conflictingService.pkiOperation(
                        Mockito.eq("intune-primary"), Mockito.any(byte[].class)))
                .thenThrow(new ScepConflictException("transaction conflict"));
        MockMvc conflictingMvc = MockMvcBuilders.standaloneSetup(new ScepController(conflictingService))
                .setControllerAdvice(new ScepExceptionAdvice())
                .build();

        conflictingMvc.perform(post("/scep/v1/intune-primary").param("operation", "PKIOperation")
                        .contentType(ScepConstants.CT_PKI_MESSAGE).content(new byte[]{1}))
                .andExpect(status().isConflict());
    }

    @Test
    void temporaryCaFailureReturnsRetryableServiceUnavailable() throws Exception {
        ScepService unavailableService = Mockito.mock(ScepService.class);
        Mockito.when(unavailableService.pkiOperation(
                        Mockito.eq("intune-primary"), Mockito.any(byte[].class)))
                .thenThrow(new CaUnavailableException("Smallstep temporarily unavailable", null));
        MockMvc unavailableMvc = MockMvcBuilders
                .standaloneSetup(new ScepController(unavailableService))
                .setControllerAdvice(new ScepExceptionAdvice())
                .build();

        unavailableMvc.perform(post("/scep/v1/intune-primary").param("operation", "PKIOperation")
                        .contentType(ScepConstants.CT_PKI_MESSAGE).content(new byte[]{1}))
                .andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Retry-After", "30"));
    }
}
