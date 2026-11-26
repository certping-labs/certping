// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import com.certping.notification.config.EmailConfig;
import com.certping.notification.enums.NotificationAction;
import com.certping.notification.enums.NotificationType;
import com.certping.notification.model.NotificationEvent;
import com.certping.notification.repository.NotificationRepository;
import tools.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.mail.javamail.JavaMailSender;

import java.io.IOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * FEATURE_PAUSED and FEATURE_RESUMED as the server publishes them (ProducerEnvelopes), deserialized
 * the way the listener does, then rendered through both email providers.
 */
class FeatureLifecycleEmailTest {

    private static final String INJECTED = "{{templateFields}} {{domain}} <a href=\"https://evil.example\">x</a>";
    private static final String ENCODED = "&#123;&#123;templateFields&#125;&#125; &#123;&#123;domain&#125;&#125; "
            + "&lt;a href=&quot;https://evil.example&quot;&gt;x&lt;/a&gt;";
    private static final String CALLOUT = "Anything you paused yourself stays paused.";
    /** A details row's label cell; the bare class name also appears in the stylesheet. */
    private static final String DETAIL_ROW = "class=\"cp-slate cp-rule cp-label-cell\"";

    private final EmailConfig emailConfig = mock(EmailConfig.class);
    private final NotificationService service = new NotificationService(mock(NotificationRepository.class),
            mock(EmailProvider.class), mock(ObjectMapper.class), emailConfig,
            mock(RoleEmailMapper.class), mock(RecipientDelivery.class), new EmailCopies(""), new SimpleMeterRegistry(),
            event -> java.util.Optional.empty());
    private final SmtpEmailService smtp = new SmtpEmailService(mock(JavaMailSender.class), new DefaultResourceLoader(),
            new DeliveryTimeouts("smtp", 30_000, 30_000, 30_000, Duration.ofSeconds(30), Duration.ofMinutes(5)));
    private final EmailService acs = new EmailService("", "noreply@example.com", new DefaultResourceLoader());

    @Test
    void thePublishedEnvelopeDeserializesWithItsFields() {
        NotificationEvent event = ProducerEnvelopes.read(ProducerEnvelopes.feature("PAUSED"));

        assertThat(event.getNotificationAction()).isEqualTo(NotificationAction.FEATURE_PAUSED);
        assertThat(event.getNotificationType()).isEqualTo(NotificationType.ACCOUNT_EVENT);
        assertThat(event.getOrganizationId()).isEqualTo(42L);
        assertThat(event.getRoles()).containsExactly("ORGANIZATION_ADMIN");
        assertThat(event.getRequestId()).isEqualTo(ProducerEnvelopes.featureKey("PAUSED"));
        assertThat(event.isDeliverOnce()).isTrue();
        assertThat(event.getTemplateFields()).containsEntry("featureName", "Certificate discovery")
                .containsEntry("organizationName", "Acme Ltd")
                .containsEntry("idempotencyKey", ProducerEnvelopes.featureKey("PAUSED"));
        assertThat(event.getTemplateFields().get("items")).asList().hasSize(2);
    }

    @Test
    void pausedSubjectNamesTheFeatureAndOrganization() {
        assertThat(FeatureLifecycleEmail.subject(ProducerEnvelopes.read(ProducerEnvelopes.feature("PAUSED"))))
                .isEqualTo("CertPing - Certificate discovery is paused for Acme Ltd");
    }

    @Test
    void resumedSubjectNamesTheFeature() {
        assertThat(FeatureLifecycleEmail.subject(ProducerEnvelopes.read(ProducerEnvelopes.feature("RESUMED"))))
                .isEqualTo("CertPing - Certificate discovery is available again");
    }

    @Test
    void subjectsFallBackStayOnOneLineAndAreCutWithAnEllipsis() {
        assertThat(FeatureLifecycleEmail.subject(event(NotificationAction.FEATURE_PAUSED, new HashMap<>())))
                .isEqualTo("CertPing - A CertPing feature is paused for your organization");

        NotificationEvent injected = event(NotificationAction.FEATURE_RESUMED,
                new HashMap<>(Map.of("featureName", "Monitoring\r\nBcc: x@example.net")));
        assertThat(FeatureLifecycleEmail.subject(injected)).doesNotContain("\r").doesNotContain("\n");

        NotificationEvent longName = event(NotificationAction.FEATURE_RESUMED,
                new HashMap<>(Map.of("featureName", "x".repeat(137) + "\uD83D\uDE00" + "y".repeat(20))));
        assertThat(FeatureLifecycleEmail.subject(longName)).as("the emoji is not split")
                .isEqualTo("CertPing - " + "x".repeat(137) + "…");
    }

    @Test
    void pausedEmailCarriesTheContractCopy() throws IOException {
        String html = render(ProducerEnvelopes.read(ProducerEnvelopes.feature("PAUSED")));

        assertThat(html)
                .contains("Certificate discovery is paused")
                .contains("Certificate discovery has been paused by CertPing. While it&#8217;s paused nothing runs "
                        + "and you aren&#8217;t billed for it.")
                .contains("Your data is kept, including the records below.")
                .contains(">Details<").contains(">Feature<")
                .contains("Discovery configurations").contains(">12<")
                .contains("Cloud accounts").contains(">3<")
                .contains("6 Oct 2026, 09:15 UTC")
                .contains("To ask about access, ")
                .contains("href=\"mailto:support@example.com\"")
                .doesNotContain("{{");
    }

    @Test
    void resumedEmailCarriesTheContractCopy() throws IOException {
        String html = render(ProducerEnvelopes.read(ProducerEnvelopes.feature("RESUMED")));

        assertThat(html)
                .contains("Certificate discovery is available again")
                .contains("Certificate discovery is turned back on.")
                .contains("The records below have resumed automatically.")
                .contains("Discovery configurations")
                .contains("Anything you paused yourself stays paused.")
                .contains("mailto:support@example.com")
                .doesNotContain("{{");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void resumedWithoutRecordsOnlySaysTheFeatureIsBackOn(List<Object> items) throws IOException {
        NotificationEvent event = ProducerEnvelopes.read(ProducerEnvelopes.feature("RESUMED", fieldsWithItems("RESUMED", items)));

        String html = render(event);

        assertThat(FeatureLifecycleEmail.subject(event)).isEqualTo("CertPing - Certificate discovery is available again");
        assertThat(html)
                .contains("Certificate discovery is turned back on.</td>")
                .doesNotContain("resumed automatically")
                .doesNotContain("Discovery configurations")
                .contains(">Feature<").contains(">When<")
                .doesNotContain("{{");
        assertThat(occurrences(html, DETAIL_ROW)).as("only the Feature and When rows").isEqualTo(2);
        assertThat(occurrences(html, CALLOUT)).isEqualTo(1);
        assertThat(html.substring(html.indexOf("is turned back on.</td>"), html.indexOf(CALLOUT)))
                .as("no copy row between the sentence and the callout")
                .doesNotContain("<td class=\"cp-slate\"");
    }

    @Test
    void resumedWithoutRecordsOrDetailsGoesStraightFromTheSentenceToTheCallout() throws IOException {
        String html = render(event(NotificationAction.FEATURE_RESUMED, new HashMap<>()));

        assertThat(html).containsPattern("A CertPing feature is turned back on\\.</td>\\s*</tr>\\s*"
                + "<tr>\\s*<td style=\"padding:0 0 28px 0;\">\\s*<table");
        assertThat(occurrences(html, CALLOUT)).isEqualTo(1);
    }

    @Test
    void pausedWithAnEmptyItemsListKeepsTheDataSentenceWithoutAList() throws IOException {
        String html = render(ProducerEnvelopes.read(ProducerEnvelopes.feature("PAUSED", fieldsWithItems("PAUSED", List.of()))));

        assertThat(html)
                .contains(">Your data is kept.</td>")
                .doesNotContain("including the records below")
                .doesNotContain("Discovery configurations")
                .doesNotContain("{{");
        assertThat(occurrences(html, DETAIL_ROW)).as("only the Feature and When rows").isEqualTo(2);
    }

    @ParameterizedTest
    @EnumSource(value = NotificationAction.class, names = {"FEATURE_PAUSED", "FEATURE_RESUMED"})
    void withoutAFeatureNameTheCopyFallsBackAndTheFeatureRowIsLeftOut(NotificationAction action) throws IOException {
        Map<String, Object> fields = new HashMap<>(Map.of("items",
                List.of(Map.of("count", 4), "not-an-object", Map.of("label", "Domains", "count", "many"))));

        String html = render(event(action, fields));

        assertThat(html)
                .contains("A CertPing feature is")
                .doesNotContain("This feature")
                .doesNotContain(">Feature<")
                .contains(">Details<").contains("Domains")
                .doesNotContain("many")
                .doesNotContain(">When<")
                .doesNotContain("{{");
    }

    @ParameterizedTest
    @EnumSource(value = NotificationAction.class, names = {"FEATURE_PAUSED", "FEATURE_RESUMED"})
    void aBareEventRendersWithoutAnEmptyDetailsPanel(NotificationAction action) throws IOException {
        String html = render(event(action, new HashMap<>()));

        assertThat(html)
                .contains("A CertPing feature is")
                .doesNotContain(">Details<")
                .doesNotContain("cp-evidence\" bgcolor")
                .doesNotContain("{{");
    }

    @ParameterizedTest
    @EnumSource(value = NotificationAction.class, names = {"FEATURE_PAUSED", "FEATURE_RESUMED"})
    void everyPublisherValueIsEscapedOnceAndCannotFormAPlaceholder(NotificationAction action) throws IOException {
        int ownLinks = links(render(ProducerEnvelopes.read(ProducerEnvelopes.feature("PAUSED")
                .replace("FEATURE_PAUSED", action.name()))));
        Map<String, Object> fields = new HashMap<>();
        fields.put("featureName", INJECTED);
        fields.put("organizationName", INJECTED);
        fields.put("occurredAt", INJECTED);
        fields.put("domain", INJECTED);
        fields.put("items", List.of(Map.of("label", INJECTED, "count", "{{featureName}}")));

        String html = render(event(action, fields));

        assertThat(html)
                .doesNotContain("<a href=\"https://evil")
                .contains(">" + ENCODED + "<")
                .contains(ENCODED + " is ")
                .doesNotContain("&amp;#123;").doesNotContain("{{");
        assertThat(links(html)).as("only the template's own links").isEqualTo(ownLinks);
    }

    @Test
    void theRawTemplateFieldsMapIsDroppedAndEveryFieldEscaped() {
        Map<String, Object> model = service.getModel(event(NotificationAction.FEATURE_PAUSED,
                new HashMap<>(Map.of("featureName", INJECTED, "nested", Map.of("note", "{{x}}")))));

        assertThat(model).doesNotContainKey("templateFields")
                .containsEntry("templateFields.featureName", ENCODED)
                .containsEntry("nested.note", "&#123;&#123;x&#125;&#125;")
                .containsEntry("templateFields.nested.note", "&#123;&#123;x&#125;&#125;");
    }

    private static int links(String html) {
        return occurrences(html, "<a ");
    }

    private static int occurrences(String html, String text) {
        return html.split(Pattern.quote(text), -1).length - 1;
    }

    /** The server's fields for the transition, with {@code items} sent as given or, when null, left out. */
    private static Map<String, Object> fieldsWithItems(String transition, List<Object> items) {
        Map<String, Object> fields = ProducerEnvelopes.featureFields(transition);
        if (items == null) {
            fields.remove("items");
        } else {
            fields.put("items", items);
        }
        return fields;
    }

    private static NotificationEvent event(NotificationAction action, Map<String, Object> fields) {
        return NotificationEvent.builder().notificationAction(action).organizationId(42L).templateFields(fields).build();
    }

    private String render(NotificationEvent event) throws IOException {
        when(emailConfig.getSupportAddress()).thenReturn("support@example.com");
        when(emailConfig.getFrontendBaseUrl()).thenReturn("https://certping.example.com");
        String template = event.getNotificationAction().name().toLowerCase().replace("_", "-");
        Map<String, Object> model = service.getModel(event);

        String html = smtp.render(template, model);
        assertThat(acs.render(template, model)).as("ACS and SMTP render alike").isEqualTo(html);
        return html;
    }
}
