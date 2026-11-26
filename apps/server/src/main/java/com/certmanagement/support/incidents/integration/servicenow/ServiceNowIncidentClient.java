// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.integration.servicenow;

import tools.jackson.databind.JsonNode;
import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.common.RequestContext;
import com.certmanagement.support.config.IncidentsProperties;
import jakarta.servlet.http.HttpServletRequest;
import com.certmanagement.support.config.GuardedHttpClients;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

@Component
public class ServiceNowIncidentClient {

    private static final Logger log = LoggerFactory.getLogger(ServiceNowIncidentClient.class);

    private final RestClient.Builder restClientBuilder;
    private final IncidentsProperties.ServiceNow properties;
    /** One pooled client for every instance; the instance URL is admin-configured, so its addresses are checked. */
    private final ClientHttpRequestFactory requestFactory;

    public ServiceNowIncidentClient(RestClient.Builder restClientBuilder, IncidentsProperties properties) {
        this(restClientBuilder, properties, false);
    }

    @Autowired
    public ServiceNowIncidentClient(RestClient.Builder restClientBuilder, IncidentsProperties properties,
                                    @Value("${app.integrations.allow-private-addresses:false}")
                                    boolean allowPrivateAddresses) {
        this.restClientBuilder = restClientBuilder;
        this.properties = properties.serviceNow();
        this.requestFactory = GuardedHttpClients.requestFactory(
                this.properties.connectTimeout(), this.properties.readTimeout(), allowPrivateAddresses);
    }

    public ServiceNowIncidentCreateResult createIncident(
            URI instanceUrl,
            String oauthScope,
            Map<String, Object> requestBody,
            Map<String, String> secrets) {
        long startedAt = System.nanoTime();
        HttpServletRequest currentRequest = RequestContext.currentRequest();
        try {
            RestClient restClient = restClient(instanceUrl);
            JsonNode response = restClient.post()
                    .uri("/api/now/v1/table/incident?sysparm_display_value=true&sysparm_input_display_value=true")
                    .headers(headers -> applyAuthentication(headers, restClient, instanceUrl, oauthScope, secrets))
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(requestBody)
                    .retrieve()
                    .body(JsonNode.class);
            RequestContext.recordDownstreamCall(currentRequest, "servicenow-itsm", 201, elapsedMillis(startedAt));
            return toCreateResult(instanceUrl, response);
        } catch (RestClientResponseException exception) {
            RequestContext.recordDownstreamCall(currentRequest, "servicenow-itsm", exception.getStatusCode().value(), elapsedMillis(startedAt));
            throw new ApiException(502, "SERVICENOW_REQUEST_FAILED", "ServiceNow incident request failed");
        } catch (ResourceAccessException exception) {
            RequestContext.recordDownstreamCall(currentRequest, "servicenow-itsm", null, elapsedMillis(startedAt));
            throw new ApiException(504, "SERVICENOW_REQUEST_TIMEOUT", "ServiceNow incident request timed out");
        } catch (RestClientException exception) {
            RequestContext.recordDownstreamCall(currentRequest, "servicenow-itsm", null, elapsedMillis(startedAt));
            log.warn(
                    "ServiceNow incident request failed instanceHost={} message={}",
                    instanceUrl.getHost(),
                    exception.getMessage());
            throw new ApiException(502, "SERVICENOW_REQUEST_FAILED", "ServiceNow incident request failed");
        }
    }

    private void applyAuthentication(
            HttpHeaders headers,
            RestClient restClient,
            URI instanceUrl,
            String oauthScope,
            Map<String, String> secrets) {
        String clientId = requiredSecret(secrets, "client_id");
        String clientSecret = requiredSecret(secrets, "client_secret");
        String accessToken = fetchAccessToken(restClient, instanceUrl, clientId, clientSecret, oauthScope);
        headers.setBearerAuth(accessToken);
    }

    private String fetchAccessToken(
            RestClient restClient,
            URI instanceUrl,
            String clientId,
            String clientSecret,
            String oauthScope) {
        long startedAt = System.nanoTime();
        HttpServletRequest currentRequest = RequestContext.currentRequest();
        LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        if (StringUtils.hasText(oauthScope)) {
            form.add("scope", oauthScope.trim());
        }

        try {
            ServiceNowAccessTokenResponse response = restClient.post()
                    .uri("/oauth_token.do")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(ServiceNowAccessTokenResponse.class);
            RequestContext.recordDownstreamCall(currentRequest, "servicenow-oauth-token", 200, elapsedMillis(startedAt));
            if (response == null || !StringUtils.hasText(response.accessToken())) {
                throw new ApiException(502, "SERVICENOW_REQUEST_FAILED", "ServiceNow OAuth token request failed");
            }
            return response.accessToken();
        } catch (RestClientResponseException exception) {
            RequestContext.recordDownstreamCall(
                    currentRequest,
                    "servicenow-oauth-token",
                    exception.getStatusCode().value(),
                    elapsedMillis(startedAt));
            log.warn(
                    "ServiceNow OAuth token request failed status={} instanceHost={} responseBody={}",
                    exception.getStatusCode().value(),
                    instanceUrl.getHost(),
                    abbreviatedBody(exception.getResponseBodyAsString()));
            throw new ApiException(502, "SERVICENOW_REQUEST_FAILED", "ServiceNow OAuth token request failed");
        } catch (ResourceAccessException exception) {
            RequestContext.recordDownstreamCall(currentRequest, "servicenow-oauth-token", null, elapsedMillis(startedAt));
            log.warn(
                    "ServiceNow OAuth token request timed out instanceHost={} message={}",
                    instanceUrl.getHost(),
                    exception.getMessage());
            throw new ApiException(504, "SERVICENOW_REQUEST_TIMEOUT", "ServiceNow OAuth token request timed out");
        } catch (RestClientException exception) {
            RequestContext.recordDownstreamCall(currentRequest, "servicenow-oauth-token", null, elapsedMillis(startedAt));
            log.warn(
                    "ServiceNow OAuth token parse/request failure instanceHost={} message={}",
                    instanceUrl.getHost(),
                    exception.getMessage());
            throw new ApiException(502, "SERVICENOW_REQUEST_FAILED", "ServiceNow OAuth token request failed");
        }
    }

    private ServiceNowIncidentCreateResult toCreateResult(URI instanceUrl, JsonNode response) {
        JsonNode result = response == null ? null : response.get("result");
        String sysId = textValue(result, "sys_id");
        String number = textValue(result, "number");
        if (!StringUtils.hasText(sysId) || !StringUtils.hasText(number)) {
            throw new ApiException(502, "SERVICENOW_REQUEST_FAILED", "ServiceNow incident request failed");
        }

        URI apiUrl = instanceUrl.resolve("/api/now/v1/table/incident/" + urlEncode(sysId));
        URI displayUrl = instanceUrl.resolve("/nav_to.do?uri=incident.do?sys_id=" + urlEncode(sysId));
        return new ServiceNowIncidentCreateResult(sysId, number, apiUrl.toString(), displayUrl.toString());
    }

    private String textValue(JsonNode node, String fieldName) {
        if (node == null) {
            return null;
        }
        JsonNode field = node.get(fieldName);
        return field == null || field.isNull() ? null : field.asString(null);
    }

    private RestClient restClient(URI instanceUrl) {
        return restClientBuilder
                .clone()
                .baseUrl(instanceUrl.toString())
                .requestFactory(requestFactory)
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    private String requiredSecret(Map<String, String> secrets, String key) {
        String value = secrets == null ? null : secrets.get(key);
        if (!StringUtils.hasText(value)) {
            throw new ApiException(500, "INTEGRATION_SECRET_REFERENCE_INVALID", "Integration secret reference is invalid");
        }
        return value;
    }

    private long elapsedMillis(long startedAt) {
        return (System.nanoTime() - startedAt) / 1_000_000L;
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String abbreviatedBody(String responseBody) {
        if (!StringUtils.hasText(responseBody)) {
            return "-";
        }
        String normalized = responseBody.replaceAll("\\s+", " ").trim();
        return normalized.length() <= 500 ? normalized : normalized.substring(0, 500) + "...";
    }

    public record ServiceNowIncidentCreateResult(
            String sysId,
            String number,
            String recordUrl,
            String displayUrl
    ) {
    }
}
