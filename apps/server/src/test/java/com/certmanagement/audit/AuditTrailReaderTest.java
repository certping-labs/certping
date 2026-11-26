// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.dto.audit.AuditEventEntryDto;
import com.certmanagement.dto.audit.AuditEventFilterRequest;
import com.certmanagement.dto.audit.AuditEventPageResponse;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** The list's window, paging, filters and read-time rendering, over a stubbed store. */
class AuditTrailReaderTest {

    static final Instant NOW = Instant.parse("2026-10-07T12:00:00Z");
    static final Instant VISIBLE_FROM = Instant.parse("2026-07-09T12:00:00Z");
    static final long ORG = 7L;
    static final int CAP = 10_000;

    private final AuditEventQueryStore store = mock(AuditEventQueryStore.class);
    private final FeatureFlagService flags = mock(FeatureFlagService.class);
    private final AuditVisibilityPolicy policy = new AuditVisibilityPolicy(flags);
    private final AuditTrailReader reader =
            new AuditTrailReader(store, Clock.fixed(NOW, ZoneOffset.UTC), CAP, 90);

    @BeforeEach
    void noFeaturesOff() {
        when(flags.disabledFeatureKeys(anyLong())).thenReturn(Set.of());
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of());
        when(store.users(anyCollection())).thenReturn(Map.of());
        when(store.organizationNames(anyCollection())).thenReturn(Map.of(ORG, "Acme"));
    }

    // ── Window ───────────────────────────────────────────────────────────

    @Test
    void aCustomerFromBeforeTheWindowIsClampedAndThePageSaysWhereTheWindowStarts() {
        AuditEventPageResponse page = read(f -> f.setFrom(OffsetDateTime.parse("2025-01-01T00:00:00Z")));

        assertThat(listed().from()).isEqualTo(VISIBLE_FROM);
        assertThat(listed().organizationId()).isEqualTo(ORG);
        assertThat(page.visibleFrom()).isEqualTo(OffsetDateTime.ofInstant(VISIBLE_FROM, ZoneOffset.UTC));
    }

    @Test
    void aCustomerWithoutFromReadsFromTheWindowAndAFromInsideItIsKept() {
        read(f -> { });
        assertThat(listed().from()).isEqualTo(VISIBLE_FROM);

        Instant inside = NOW.minus(Duration.ofDays(3));
        read(f -> f.setFrom(OffsetDateTime.ofInstant(inside, ZoneOffset.UTC)));
        assertThat(listedAll().get(1).from()).isEqualTo(inside);
    }

    @Test
    void aRangeEntirelyBeforeTheWindowIsAnEmptyPageWithoutAQuery() {
        AuditEventPageResponse page = read(f -> {
            f.setFrom(OffsetDateTime.parse("2025-01-01T00:00:00Z"));
            f.setTo(OffsetDateTime.parse("2025-02-01T00:00:00Z"));
        });

        assertThat(page.content()).isEmpty();
        assertThat(page.empty()).isTrue();
        assertThat(page.last()).isTrue();
        assertThat(page.totalElements()).isZero();
        assertThat(page.visibleFrom()).isNotNull();
        verify(store, never()).list(any(), any(), anyLong(), anyInt());
    }

    @Test
    void aSuperAdminIsNotClampedAndReadsTheOrganizationTheyNameOrEvery() {
        AuditEventPageResponse page = reader.read(filter(f -> f.setFrom(OffsetDateTime.parse("2024-01-01T00:00:00Z"))),
                null, null, false, policy.viewer(true, 99L));

        assertThat(listed().from()).isEqualTo(Instant.parse("2024-01-01T00:00:00Z"));
        assertThat(listed().organizationId()).isEqualTo(99L);
        assertThat(page.visibleFrom()).as("not clamped").isNull();

        reader.read(filter(f -> { }), null, null, false, policy.viewer(true, null));
        assertThat(listedAll().get(1).from()).isNull();
        assertThat(listedAll().get(1).organizationId()).isNull();
    }

    @Test
    void fromAfterToIsRefused() {
        assertThatThrownBy(() -> read(f -> {
            f.setFrom(OffsetDateTime.parse("2026-10-02T00:00:00Z"));
            f.setTo(OffsetDateTime.parse("2026-10-01T00:00:00Z"));
        })).isInstanceOf(BadRequestException.class);
    }

    // ── Paging ───────────────────────────────────────────────────────────

    @Test
    void aCursorTogetherWithPageIsRefused() {
        String cursor = new AuditCursor(NOW.toString(), 5, 1, 30, false, false).encode();

        assertThatThrownBy(() -> reader.read(filter(f -> f.setCursor(cursor)), 0, 20, false, customer()))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("cursor");
        verifyNoInteractions(store);
    }

    @Test
    void anOffsetPastTheCountCapIsRefusedAndOneAtItIsServedEmpty() {
        assertThatThrownBy(() -> reader.read(filter(f -> { }), 101, 100, false, customer()))
                .isInstanceOf(BadRequestException.class).hasMessageContaining("10000");
        assertThatThrownBy(() -> reader.read(filter(f -> { }), -1, 20, false, customer()))
                .isInstanceOf(BadRequestException.class);

        when(store.countUpTo(any(), eq(CAP + 1))).thenReturn(OptionalLong.of(CAP + 1));
        AuditEventPageResponse page = reader.read(filter(f -> { }), 100, 100, false, customer());
        assertThat(page.content()).isEmpty();
        assertThat(page.totalElements()).isEqualTo(CAP);
        assertThat(page.totalElementsCapped()).isTrue();
        verify(store, never()).list(any(), any(), anyLong(), anyInt());
    }

    @Test
    void sizeDefaultsToTwentyAndIsAtMostAHundred() {
        assertThat(reader.read(filter(f -> { }), null, null, false, customer()).size()).isEqualTo(20);
        assertThat(reader.read(filter(f -> { }), null, 5000, false, customer()).size()).isEqualTo(100);
        verify(store).list(any(), isNull(), eq(0L), eq(101));
    }

    @Test
    void aFullFirstPageCountsUpToTheCapAndHandsOutACursorCarryingTheTotal() {
        when(store.list(any(), isNull(), eq(0L), eq(3))).thenReturn(rows(3));
        when(store.countUpTo(any(), eq(CAP + 1))).thenReturn(OptionalLong.of(CAP + 1));

        AuditEventPageResponse page = reader.read(filter(f -> { }), null, 2, false, customer());

        assertThat(page.content()).extracting(AuditEventEntryDto::id).containsExactly(100L, 99L);
        assertThat(page.totalElements()).isEqualTo(CAP);
        assertThat(page.totalElementsCapped()).isTrue();
        assertThat(page.totalPages()).isEqualTo(5000);
        assertThat(page.first()).isTrue();
        assertThat(page.last()).isFalse();
        AuditCursor next = AuditCursor.decode(page.nextCursor());
        assertThat(next.id()).isEqualTo(99L);
        assertThat(next.number()).isEqualTo(1);
        assertThat(next.total()).isEqualTo(CAP);
        assertThat(next.capped()).isTrue();
    }

    @Test
    void aCursorPageIsNotCountedAgainAndKeepsTheFirstPagesTotal() {
        String cursor = new AuditCursor("2026-10-07T11:00:00.123456Z", 99, 1, 42, false, false).encode();
        when(store.list(any(), any(), eq(0L), eq(3))).thenReturn(rows(2));

        AuditEventPageResponse page = reader.read(filter(f -> f.setCursor(cursor)), null, 2, false, customer());

        ArgumentCaptor<AuditEventQueryStore.Keyset> after = ArgumentCaptor.forClass(AuditEventQueryStore.Keyset.class);
        verify(store).list(any(), after.capture(), eq(0L), eq(3));
        assertThat(after.getValue().occurredAt()).isEqualTo(Instant.parse("2026-10-07T11:00:00.123456Z"));
        assertThat(after.getValue().id()).isEqualTo(99L);
        verify(store, never()).countUpTo(any(), anyInt());
        assertThat(page.number()).isEqualTo(1);
        assertThat(page.first()).isFalse();
        assertThat(page.totalElements()).isEqualTo(42);
        assertThat(page.last()).isTrue();
        assertThat(page.nextCursor()).isNull();
    }

    @Test
    void aCursorKeepsTheOrderItWasMadeFor() {
        String ascending = new AuditCursor(NOW.toString(), 9, 1, 42, false, true).encode();

        reader.read(filter(f -> f.setCursor(ascending)), null, 2, false, customer());

        assertThat(listed().ascending()).isTrue();
    }

    @Test
    void aMalformedCursorIsA400() {
        assertThatThrownBy(() -> read(f -> f.setCursor("not-a-cursor"))).isInstanceOf(BadRequestException.class);
        assertThatThrownBy(() -> read(f -> f.setCursor(new AuditCursor(NOW.toString(), 0, 1, 1, false, false).encode())))
                .isInstanceOf(BadRequestException.class);
    }

    @Test
    void aTimedOutCountFallsBackToALowerBoundThatKeepsNextEnabled() {
        when(store.list(any(), isNull(), eq(40L), eq(21))).thenReturn(rows(21));
        when(store.countUpTo(any(), anyInt())).thenReturn(OptionalLong.empty());

        AuditEventPageResponse page = reader.read(filter(f -> { }), 2, 20, false, customer());

        assertThat(page.totalElementsCapped()).isTrue();
        assertThat(page.totalElements()).isEqualTo(61);
        assertThat(page.last()).isFalse();
        assertThat(page.nextCursor()).isNotNull();
    }

    @Test
    void aShortFirstPageIsExactWithoutACount() {
        when(store.list(any(), isNull(), eq(0L), eq(21))).thenReturn(rows(3));

        AuditEventPageResponse page = read(f -> { });

        assertThat(page.totalElements()).isEqualTo(3);
        assertThat(page.totalElementsCapped()).isFalse();
        assertThat(page.last()).isTrue();
        assertThat(page.nextCursor()).isNull();
        verify(store, never()).countUpTo(any(), anyInt());
    }

    // ── Filters ──────────────────────────────────────────────────────────

    @Test
    void everyFilterReachesTheQuery() {
        read(f -> {
            f.setUserId(42);
            f.setActorType("system");
            f.setEvent("credential.deleted");
            f.setCategory("CREDENTIALS");
            f.setResourceType("credential");
            f.setResourceId(12L);
            f.setResourceRef(" cred_1 ");
            f.setResourceName("prod-dns");
            f.setOutcome("FAILURE");
            f.setRequestId("req-9");
            f.setCorrelationId("corr-9");
        });

        AuditEventQuery q = listed();
        assertThat(q.userId()).isEqualTo(42);
        assertThat(q.actorType()).isEqualTo(AuditActorType.SYSTEM);
        assertThat(q.events()).containsExactly("credential.deleted");
        assertThat(q.category()).isEqualTo(AuditCategory.CREDENTIALS);
        assertThat(q.resourceType()).isEqualTo("CREDENTIAL");
        assertThat(q.resourceId()).isEqualTo(12L);
        assertThat(q.resourceRef()).isEqualTo("cred_1");
        assertThat(q.resourceName()).isEqualTo("prod-dns");
        assertThat(q.outcome()).isEqualTo(AuditOutcome.FAILURE);
        assertThat(q.requestId()).isEqualTo("req-9");
        assertThat(q.correlationId()).isEqualTo("corr-9");
        assertThat(q.hiddenFeatureKeys()).as("events of features that are off stay listed").isEmpty();
    }

    @Test
    void actionIsMatchedAsAnActionCode() {
        read(f -> f.setAction("USER_CREATED"));
        read(f -> f.setAction("delete"));

        List<AuditEventQuery> queries = listedAll();
        assertThat(queries.get(0).action()).isEqualTo("USER_CREATED");
        assertThat(queries.get(0).events()).isNull();
        assertThat(queries.get(1).action()).isEqualTo("DELETE");
    }

    @Test
    void statusIsTheLegacyNameOfOutcome() {
        read(f -> f.setStatus("success"));
        assertThat(listed().outcome()).isEqualTo(AuditOutcome.SUCCESS);

        assertThatThrownBy(() -> read(f -> {
            f.setStatus("SUCCESS");
            f.setOutcome("FAILURE");
        })).isInstanceOf(BadRequestException.class);
    }

    @Test
    void malformedFiltersAreA400() {
        List<Consumer<AuditEventFilterRequest>> malformed = List.of(
                f -> f.setActorType("ROBOT"),
                f -> f.setCategory("NOPE"),
                f -> f.setOutcome("MAYBE"),
                f -> f.setAction("drop table"),
                f -> f.setResourceType("x y"),
                f -> f.setEvent("Not An Event"),
                f -> f.setRequestId("r".repeat(257)));
        for (Consumer<AuditEventFilterRequest> filter : malformed) {
            assertThatThrownBy(() -> read(filter)).isInstanceOf(BadRequestException.class);
        }
    }

    @Test
    void timestampAscendingIsTheOnlyOtherOrder() {
        reader.read(filter(f -> { }), null, null, true, customer());
        assertThat(listed().ascending()).isTrue();
    }

    // ── Rendering ────────────────────────────────────────────────────────

    @Test
    void memberTargetsAreRenderedFromTheLiveUsersRowAndAFormerMemberOtherwise() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                row(3).event("member.created").resourceType("USER").resourceId(51L).resourceRef("51")
                        .summary("Added a member").build(),
                row(2).event("auth.account_locked").resourceType("USER").resourceId(52L).resourceRef("52")
                        .summary("a member's account was locked after 5 failed sign-ins").build(),
                row(1).event("auth.account_locked").resourceType("USER").resourceId(53L).resourceRef("53")
                        .summary("a member's account was locked after 5 failed sign-ins").build()));
        when(store.users(anyCollection())).thenReturn(Map.of(
                51, new AuditEventQueryStore.LiveUser("bob@acme.test", "Bob Builder", ORG),
                52, new AuditEventQueryStore.LiveUser("carol@acme.test", null, ORG)));

        List<AuditEventEntryDto> entries = read(f -> { }).content();

        assertThat(entries).extracting(AuditEventEntryDto::summary).containsExactly(
                "Added Bob Builder",
                "carol@acme.test's account was locked after 5 failed sign-ins",
                "A former member's account was locked after 5 failed sign-ins");
        assertThat(entries).extracting(AuditEventEntryDto::resourceName)
                .containsExactly("Bob Builder", "carol@acme.test", null);
    }

    @Test
    void theActorIsTheLiveEmailAndTheStoredLabelOrFormerMemberOrCertPing() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                row(3).actorUserId(42).actorLabel("Alice Admin").build(),
                row(2).actorUserId(43).actorLabel("Former member").build(),
                row(1).actorType("SYSTEM").actorUserId(null).actorLabel(null).build()));
        when(store.users(anyCollection())).thenReturn(Map.of(
                42, new AuditEventQueryStore.LiveUser("alice@acme.test", "Alice A.", ORG)));

        List<AuditEventEntryDto> entries = read(f -> { }).content();

        assertThat(entries).extracting(AuditEventEntryDto::actorName)
                .containsExactly("Alice Admin", "Former member", "CertPing (automatic)");
        assertThat(entries).extracting(AuditEventEntryDto::userEmail)
                .containsExactly("alice@acme.test", null, null);
    }

    @Test
    void aStaffRowReadsAsCertPingSupportToCustomersButNotToSuperAdmins() {
        AuditEventRecord staff = row(1).actorUserId(1).actorLabel("Sam Support").actorStaff(true)
                .ipAddress("198.51.100.4").userAgent("curl").build();
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(staff));
        when(store.users(anyCollection())).thenReturn(Map.of(1, new AuditEventQueryStore.LiveUser("sam@example.com", "Sam", null)));

        AuditEventEntryDto customer = read(f -> { }).content().get(0);
        assertThat(customer.actorName()).isEqualTo("Platform administrator");
        assertThat(customer.userId()).isNull();
        assertThat(customer.userEmail()).isNull();
        assertThat(customer.ipAddress()).isNull();
        assertThat(customer.userAgent()).isNull();

        AuditEventEntryDto platform = reader.read(filter(f -> { }), null, null, false, policy.viewer(true, ORG))
                .content().get(0);
        assertThat(platform.actorName()).isEqualTo("Sam Support");
        assertThat(platform.userEmail()).isEqualTo("sam@example.com");
        assertThat(platform.ipAddress()).isEqualTo("198.51.100.4");
    }

    @Test
    void aDeletedOrganizationReadsAsSuchToCustomersAndWithItsIdToSuperAdmins() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(row(1).organizationId(66L).build()));
        when(store.organizationNames(anyCollection())).thenReturn(Map.of());

        assertThat(read(f -> { }).content().get(0).organizationName()).isEqualTo("Deleted organization");
        assertThat(reader.read(filter(f -> { }), null, null, false, policy.viewer(true, null)).content().get(0)
                .organizationName()).isEqualTo("Deleted organization (#66)");
    }

    @Test
    void aFailureReadsWithItsReasonRenderedFromTheCode() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                row(2).outcome("FAILURE").errorCode("PERMISSION_DENIED").build(),
                row(1).outcome("FAILURE").errorCode("INTERNAL_ERROR").requestId("req-77").build()));

        List<AuditEventEntryDto> entries = read(f -> { }).content();

        assertThat(entries.get(0).reason()).isEqualTo("You don't have permission to do this.");
        assertThat(entries.get(1).reason()).contains("req-77");
    }

    @Test
    void detailsStayAJsonStringOfAttributesAndChangesWithoutTheStorageKind() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(row(1).details(
                "{\"kind\":\"event\",\"changes\":[{\"field\":\"name\",\"before\":\"a\",\"after\":\"b\"}],"
                        + "\"attributes\":{\"credentialType\":\"DNS\"}}").build()));

        AuditEventEntryDto entry = read(f -> { }).content().get(0);

        assertThat(entry.details())
                .isEqualTo("{\"attributes\":{\"credentialType\":\"DNS\"},\"changes\":[{\"field\":\"name\",\"before\":\"a\",\"after\":\"b\"}]}");
        assertThat(entry.changes()).containsExactly(new AuditEventEntryDto.AuditChangeDto("name", "a", "b"));
    }

    @Test
    void eventsOfAFeatureThatIsOffStayListedMarkedFeatureOff() {
        when(flags.disabledFeatureKeys(ORG)).thenReturn(Set.of(FeatureFlags.CREDENTIALS_MANAGEMENT));
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                row(2).event("credential.deleted").featureKey(FeatureFlags.CREDENTIALS_MANAGEMENT).build(),
                row(1).event("member.created").featureKey(null).build()));

        List<AuditEventEntryDto> entries = read(f -> { }).content();

        assertThat(entries).extracting(AuditEventEntryDto::featureOff).containsExactly(true, false);
        assertThat(listed().hiddenFeatureKeys()).isEmpty();
    }

    @Test
    void aSuperAdminAcrossOrganizationsSeesFeatureOffPerRowsOrganization() {
        when(flags.disabledFeatureKeysFor(anyCollection(), anyCollection()))
                .thenReturn(Map.of(8L, Set.of(FeatureFlags.CREDENTIALS_MANAGEMENT), ORG, Set.of()));
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                row(2).organizationId(8L).featureKey(FeatureFlags.CREDENTIALS_MANAGEMENT).build(),
                row(1).organizationId(ORG).featureKey(FeatureFlags.CREDENTIALS_MANAGEMENT).build()));

        List<AuditEventEntryDto> entries = reader.read(filter(f -> { }), null, null, false, policy.viewer(true, null))
                .content();

        assertThat(entries).extracting(AuditEventEntryDto::featureOff).containsExactly(true, false);
    }

    @Test
    void aHundredRowPageAcrossFiftyOrganizationsLooksFeatureStatesUpOnce() {
        List<AuditEventRecord> rows = new ArrayList<>();
        Map<Long, Set<String>> off = new java.util.HashMap<>();
        for (int i = 0; i < 100; i++) {
            long org = 1000 + i % 50;
            String feature = i % 3 == 0 ? FeatureFlags.DISCOVERY : FeatureFlags.CREDENTIALS_MANAGEMENT;
            rows.add(row(200 - i).organizationId(org).featureKey(feature).build());
            off.put(org, org % 2 == 0 ? Set.of(FeatureFlags.DISCOVERY) : Set.of());
        }
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(rows);
        when(flags.disabledFeatureKeysFor(anyCollection(), anyCollection())).thenReturn(off);

        List<AuditEventEntryDto> entries = reader.read(filter(f -> { }), null, 100, false, policy.viewer(true, null))
                .content();

        verify(flags, org.mockito.Mockito.times(1)).disabledFeatureKeysFor(anyCollection(), anyCollection());
        verify(flags, never()).disabledFeatureKeys(anyLong());
        for (int i = 0; i < 100; i++) {
            long org = 1000 + i % 50;
            boolean discovery = i % 3 == 0;
            assertThat(entries.get(i).featureOff()).as("row " + i).isEqualTo(discovery && org % 2 == 0);
        }
    }

    @Test
    void aSingleOrganizationsPageUsesItsCachedLookupNotTheBatch() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                row(1).featureKey(FeatureFlags.CREDENTIALS_MANAGEMENT).build()));

        read(f -> { });

        verify(flags, never()).disabledFeatureKeysFor(anyCollection(), anyCollection());
        verify(flags, org.mockito.Mockito.times(1)).disabledFeatureKeys(ORG);
    }

    @Test
    void aMemberRowWithoutATargetIdKeepsAMember() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                row(1).event("auth.account_locked").resourceType("USER").resourceId(null).resourceRef(null)
                        .summary("a member's account was locked after 5 failed sign-ins").build()));

        assertThat(read(f -> { }).content().get(0).summary())
                .isEqualTo("A member's account was locked after 5 failed sign-ins");
    }

    @Test
    void everyQueryCarriesWhetherASuperAdminAsks() {
        read(f -> { });
        reader.read(filter(f -> { }), null, null, false, policy.viewer(true, null));

        assertThat(listedAll()).extracting(AuditEventQuery::superAdmin).containsExactly(false, true);
    }

    @Test
    void theRequesterOfASystemRowIsRenderedFromTheBatchedUsersLookup() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                system(5).details(requested("61")).build(),
                system(4).details(requested("62")).build(),
                system(3).details(requested("63")).build(),
                system(2).details(requested("64")).build(),
                system(1).build()));
        when(store.users(anyCollection())).thenReturn(Map.of(
                61, new AuditEventQueryStore.LiveUser("dana@acme.test", "dana", ORG),
                62, new AuditEventQueryStore.LiveUser("erin@acme.test", null, ORG),
                // A super admin: Platform administrator to members. Being in no (or another) organization is not enough.
                64, new AuditEventQueryStore.LiveUser("sam@example.com", "Sam Support", null, true, false)));

        List<AuditEventEntryDto> entries = read(f -> { }).content();

        assertThat(entries).extracting(AuditEventEntryDto::requestedByName).containsExactly(
                "dana", "erin@acme.test", "a former member", "Platform administrator", null);
        ArgumentCaptor<java.util.Collection<Integer>> ids = ArgumentCaptor.forClass(java.util.Collection.class);
        verify(store, org.mockito.Mockito.times(1)).users(ids.capture());
        assertThat(ids.getValue()).contains(61, 62, 63, 64);
        assertThat(entries.get(0).details()).as("the raw id stays out of a customer's details")
                .isEqualTo("{\"attributes\":{\"items\":\"12\"}}");
    }

    @Test
    void aSuperAdminSeesTheRequesterAndTheRawId() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(system(1).details(requested("64")).build()));
        when(store.users(anyCollection())).thenReturn(Map.of(
                64, new AuditEventQueryStore.LiveUser("sam@example.com", "Sam Support", null)));

        AuditEventEntryDto entry = reader.read(filter(f -> { }), null, null, false, policy.viewer(true, ORG))
                .content().get(0);

        assertThat(entry.requestedByName()).isEqualTo("Sam Support");
        assertThat(entry.details()).contains("\"requestedBy\":\"64\"");
    }

    @Test
    void theRequesterOfAStaffRowIsCertPingSupportToCustomers() {
        when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                row(1).actorStaff(true).details(requested("61")).build()));
        when(store.users(anyCollection())).thenReturn(Map.of(
                61, new AuditEventQueryStore.LiveUser("dana@acme.test", "Dana", ORG)));

        assertThat(read(f -> { }).content().get(0).requestedByName()).isEqualTo("Platform administrator");
    }

    private static String requested(String userId) {
        return "{\"kind\":\"event\",\"attributes\":{\"items\":\"12\",\"requestedBy\":\"" + userId + "\"}}";
    }

    private static AuditEventRecord.AuditEventRecordBuilder system(long id) {
        return row(id).event("feature.paused").actorType("SYSTEM").actorUserId(null).actorLabel("CertPing (automatic)")
                .summary("Paused 12 records because the feature 'Deployments' was turned off");
    }

    @Test
    void everyCustomerEventOfTheCatalogRendersThroughTheReadPath() {
        Set<String> off = Set.of(FeatureFlags.CREDENTIALS_MANAGEMENT, FeatureFlags.CERTIFICATE_DEPLOYMENT,
                FeatureFlags.DISCOVERY);
        when(flags.disabledFeatureKeys(ORG)).thenReturn(off);
        when(store.users(anyCollection())).thenReturn(Map.of(
                51, new AuditEventQueryStore.LiveUser("bob@acme.test", "bob builder", ORG),
                61, new AuditEventQueryStore.LiveUser("dana@acme.test", "dana", ORG)));
        List<AuditEventType> catalog = java.util.Arrays.stream(AuditEventType.values())
                .filter(e -> e.visibility() == AuditVisibility.CUSTOMER).toList();
        assertThat(catalog).hasSizeGreaterThan(40);

        for (AuditEventType type : catalog) {
            boolean requested = type.allowedAttributes().contains("requestedBy");
            AuditSubject subject = AuditSubject.builder()
                    .name(type.rendersTargetWhenRead() ? null : "prod").domain("example.com").provider("Azure")
                    .count(3).format("PEM").attributes(requested ? Map.of("requestedBy", "61") : Map.of()).build();
            String details = requested ? "{\"kind\":\"event\",\"attributes\":{\"requestedBy\":\"61\"}}" : null;
            AuditEventRecord.AuditEventRecordBuilder base = row(1).event(type.key()).category(type.category().name())
                    .featureKey(type.featureKey()).action(type.action()).resourceType(type.resourceType().name())
                    .details(details);
            if (type.rendersTargetWhenRead()) {
                base.resourceId(51L).resourceRef("51");
            }
            if (requested) {
                base.actorType("SYSTEM").actorUserId(null).actorLabel("CertPing (automatic)");
            }
            when(store.list(any(), any(), anyLong(), anyInt())).thenReturn(List.of(
                    base.id(2).outcome("SUCCESS").summary(type.summary(subject)).build(),
                    base.id(1).outcome("FAILURE").errorCode("PERMISSION_DENIED").summary(type.failure(subject)).build()));

            List<AuditEventEntryDto> entries = read(f -> { }).content();

            assertThat(entries).as(type.key()).hasSize(2).allSatisfy(entry -> {
                assertThat(entry.summary()).as(type.key()).isNotBlank();
                assertThat(entry.event()).isEqualTo(type.key());
                assertThat(entry.category()).isEqualTo(type.category().name());
                assertThat(entry.featureOff()).as(type.key()).isEqualTo(type.featureKey() != null && off.contains(type.featureKey()));
                assertThat(entry.requestedByName()).as(type.key()).isEqualTo(requested ? "dana" : null);
                assertThat(entry.details()).as(type.key()).isNull();
                if (type.rendersTargetWhenRead()) {
                    assertThat(entry.summary()).as(type.key()).contains("bob builder")
                            .doesNotContainIgnoringCase(AuditEventType.STORED_MEMBER + " ");
                }
            });
            assertThat(entries.get(1).reason()).as(type.key()).isEqualTo("You don't have permission to do this.");
            assertThat(entries.get(0).reason()).isNull();
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private AuditVisibilityPolicy.Viewer customer() {
        return policy.viewer(false, ORG);
    }

    private AuditEventPageResponse read(Consumer<AuditEventFilterRequest> setUp) {
        return reader.read(filter(setUp), null, null, false, customer());
    }

    private static AuditEventFilterRequest filter(Consumer<AuditEventFilterRequest> setUp) {
        AuditEventFilterRequest filter = new AuditEventFilterRequest();
        setUp.accept(filter);
        return filter;
    }

    private AuditEventQuery listed() {
        return listedAll().get(0);
    }

    private List<AuditEventQuery> listedAll() {
        ArgumentCaptor<AuditEventQuery> query = ArgumentCaptor.forClass(AuditEventQuery.class);
        verify(store, org.mockito.Mockito.atLeastOnce()).list(query.capture(), any(), anyLong(), anyInt());
        return query.getAllValues();
    }

    static List<AuditEventRecord> rows(int count) {
        List<AuditEventRecord> rows = new ArrayList<>();
        IntStream.range(0, count).forEach(i -> rows.add(row(100 - i).build()));
        return rows;
    }

    static AuditEventRecord.AuditEventRecordBuilder row(long id) {
        return AuditEventRecord.builder()
                .id(id)
                .occurredAt(NOW.minusSeconds(id))
                .event("organization.updated")
                .category("ORGANIZATION")
                .organizationId(ORG)
                .actorType("USER")
                .actorUserId(42)
                .actorLabel("Alice Admin")
                .action("UPDATE")
                .resourceType("ORGANIZATION")
                .outcome("SUCCESS")
                .summary("Changed the organization's settings");
    }
}
