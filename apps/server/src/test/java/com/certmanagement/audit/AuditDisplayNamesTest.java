// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The actor contract the read side renders. */
class AuditDisplayNamesTest {

    @Test
    void anActorReadsAsItsLabelFormerMemberOrUnknown() {
        assertThat(AuditDisplayNames.actor(AuditActorType.USER, 7, "Alice Admin")).isEqualTo("Alice Admin");
        assertThat(AuditDisplayNames.actor(AuditActorType.USER, 7, AuditEventStore.ERASED_ACTOR_LABEL))
                .isEqualTo("Former member");
        assertThat(AuditDisplayNames.actor(AuditActorType.USER, 7, null)).as("a null label with a user id")
                .isEqualTo("Former member");
        assertThat(AuditDisplayNames.actor(AuditActorType.ANONYMOUS, null, null))
                .as("an anonymous row").isEqualTo("Unknown");
        assertThat(AuditDisplayNames.actor(AuditActorType.SYSTEM, null, null)).isEqualTo(AuditContext.SYSTEM_LABEL);
    }

    @Test
    void aMemberTargetIsRenderedFromTheLiveNameElseAFormerMember() {
        assertThat(AuditDisplayNames.memberSummary("Added a member", "Bob Builder")).isEqualTo("Added Bob Builder");
        assertThat(AuditDisplayNames.memberSummary("Changed a member's roles", null))
                .isEqualTo("Changed a former member's roles");
        assertThat(AuditDisplayNames.memberSummary("Changed a member's roles", "  ")).isEqualTo("Changed a former member's roles");
    }

    @Test
    void onlyTheFallbackPhraseIsCapitalisedNeverALiveNameOrEmail() {
        String locked = "a member's account was locked after 5 failed sign-ins";
        assertThat(AuditDisplayNames.memberSummary(locked, null))
                .isEqualTo("A former member's account was locked after 5 failed sign-ins");
        assertThat(AuditDisplayNames.memberSummary(locked, "dana"))
                .as("a lowercase display name keeps its case").isEqualTo("dana's account was locked after 5 failed sign-ins");
        assertThat(AuditDisplayNames.memberSummary(locked, "carol@acme.test"))
                .as("an email keeps its case").isEqualTo("carol@acme.test's account was locked after 5 failed sign-ins");
        assertThat(AuditDisplayNames.memberSummary("Added a member", null)).as("not at the start")
                .isEqualTo("Added a former member");
        assertThat(AuditDisplayNames.memberSummary("Added a member", "dana")).isEqualTo("Added dana");
    }

    @Test
    void aRowWithoutATargetKeepsAMemberCapitalisedAtTheStart() {
        assertThat(AuditDisplayNames.unidentifiedMemberSummary("a member's account was locked"))
                .isEqualTo("A member's account was locked");
        assertThat(AuditDisplayNames.unidentifiedMemberSummary("Added a member")).isEqualTo("Added a member");
        assertThat(AuditDisplayNames.unidentifiedMemberSummary(null)).isNull();
    }

    @Test
    void aSummaryWithoutThePlaceholderIsLeftAsItIs() {
        assertThat(AuditDisplayNames.memberSummary("Added Bob", "Carol")).isEqualTo("Added Bob");
        assertThat(AuditDisplayNames.memberSummary("Removed a membership", "Carol")).isEqualTo("Removed a membership");
        assertThat(AuditDisplayNames.memberSummary(null, "Carol")).isNull();
    }

    @Test
    void aGoneOrganizationReadsAsDeletedAndWithItsIdOnThePlatform() {
        assertThat(AuditDisplayNames.organization("Acme")).isEqualTo("Acme");
        assertThat(AuditDisplayNames.organization(null)).isEqualTo("Deleted organization");
        assertThat(AuditDisplayNames.organizationForPlatform(42L, null)).isEqualTo("Deleted organization (#42)");
        assertThat(AuditDisplayNames.organizationForPlatform(42L, "Acme")).isEqualTo("Acme");
        assertThat(AuditDisplayNames.organizationForPlatform(null, null)).isEqualTo("Deleted organization");
    }

    @Test
    void aRequesterReadsAsTheLiveNameUnchangedElseAFormerMember() {
        assertThat(AuditDisplayNames.requester("dana")).isEqualTo("dana");
        assertThat(AuditDisplayNames.requester("erin@acme.test")).isEqualTo("erin@acme.test");
        assertThat(AuditDisplayNames.requester(null)).isEqualTo("a former member");
        assertThat(AuditDisplayNames.requester(" ")).isEqualTo("a former member");
    }
}
