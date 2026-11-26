// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * How the read side names what a row only stores by id. Rows keep no organization name and no
 * member-target name, so a renamed organization reads under its current name and an erased member
 * leaves no name behind. The read API looks the live name up and renders it through these, so every
 * view says the same thing once the record is gone.
 *
 * <ul>
 *   <li>Organization: customers see the live name, else "Deleted organization"; the platform view adds
 *       the id, "Deleted organization (#42)", so support can still tell trails apart.</li>
 *   <li>Member targeted by a {@link AuditEventType#rendersTargetWhenRead()} event: the summary is
 *       rendered again with {@link #member(String)} in place of the stored "a member"
 *       ({@link #memberSummary}): the member's live name as it is (never re-cased), else "a former
 *       member", which is capitalised when it starts the sentence ("A former member's account was
 *       locked ..."). A row with no target id keeps "a member" ("A member" at the start).</li>
 *   <li>Who asked for a system or agent row ({@code attributes.requestedBy}, a user id): rendered when
 *       read as {@link #requester}: the live display name as it is, else the email, else "a former
 *       member". To a customer, a requester who is not a member of the trail's organization (a platform
 *       account) reads as {@link #STAFF}, as does any requester of a staff row. The raw id stays out of
 *       customer responses.</li>
 *   <li>A super admin acting in another organization's trail ({@code actor_staff}) reads to the
 *       customer as {@link #STAFF}, with nothing of who or from where; the platform sees the person.</li>
 *   <li>Actor ({@link #actor}), as the read side renders it: the stored {@code actor_label} when there is one
 *       ("Former member" once an erasure pseudonymised it); a {@code NULL} label with a non-null
 *       {@code actor_user_id} also reads "Former member" (the user was gone, or had no name or email, when
 *       the row was written); SYSTEM rows read "CertPing (automatic)"; ANONYMOUS rows with neither id nor
 *       label read as "Unknown". An anonymous row written
 *       into a customer's trail on purpose (a single sign-on attempt that matched no member) stores the
 *       label {@link #SOMEONE}, and reads as it.</li>
 * </ul>
 */
public final class AuditDisplayNames {

    public static final String DELETED_ORGANIZATION = "Deleted organization";
    public static final String FORMER_MEMBER = "a former member";
    /** An actor with no name left: erased, or gone before the row was written. */
    public static final String FORMER_ACTOR = AuditEventStore.ERASED_ACTOR_LABEL;
    /** An actor the row does not know: anonymous. */
    public static final String UNKNOWN_ACTOR = "Unknown";
    /** Who a customer's trail names for an attempt by someone not identified (stored as the label). */
    public static final String SOMEONE = "Someone";
    /** Who a customer's trail names for CertPing's staff (a super admin acting in their organization). */
    public static final String STAFF = "Platform administrator";

    private static final Pattern STORED_MEMBER = Pattern.compile(
            "\\b" + Pattern.quote(AuditEventType.STORED_MEMBER) + "\\b", Pattern.CASE_INSENSITIVE);

    private AuditDisplayNames() {
    }

    /** The organization as a customer reads it. */
    public static String organization(String liveName) {
        return isBlank(liveName) ? DELETED_ORGANIZATION : liveName;
    }

    /** The organization as the platform (super admin) view reads it. */
    public static String organizationForPlatform(Long organizationId, String liveName) {
        if (!isBlank(liveName)) {
            return liveName;
        }
        return organizationId == null ? DELETED_ORGANIZATION : DELETED_ORGANIZATION + " (#" + organizationId + ")";
    }

    /** Who acted, as every view reads it; see the class comment for the rules. */
    public static String actor(AuditActorType type, Integer actorUserId, String actorLabel) {
        if (type == AuditActorType.SYSTEM) {
            return isBlank(actorLabel) ? AuditContext.SYSTEM_LABEL : actorLabel;
        }
        if (!isBlank(actorLabel)) {
            return actorLabel;
        }
        return actorUserId != null ? FORMER_ACTOR : UNKNOWN_ACTOR;
    }

    /**
     * Who asked for a system or agent action, as read: the live name (display name, else email; never
     * re-cased), else "a former member".
     */
    public static String requester(String liveName) {
        return member(liveName);
    }

    /** A member targeted by an event, rendered into its summary when read. */
    public static String member(String liveName) {
        return isBlank(liveName) ? FORMER_MEMBER : liveName;
    }

    /**
     * A member-targeted summary as it reads: the first stored "a member" replaced by the member's live
     * name, else "a former member". A live name or email is never re-cased: only the fallback phrase is
     * capitalised when it starts the sentence ("A former member's account was locked ..."). A summary
     * without the placeholder (a row written before the rule, or a template that names no member) is
     * returned as it is.
     */
    public static String memberSummary(String storedSummary, String liveName) {
        if (storedSummary == null) {
            return null;
        }
        Matcher placeholder = STORED_MEMBER.matcher(storedSummary);
        if (!placeholder.find()) {
            return storedSummary;
        }
        String name = isBlank(liveName) ? phrase(FORMER_MEMBER, placeholder.start() == 0) : liveName;
        return storedSummary.substring(0, placeholder.start()) + name + storedSummary.substring(placeholder.end());
    }

    /**
     * A member-targeted summary of a row that names no member (no target id): the stored "a member" is
     * kept, capitalised when it starts the sentence.
     */
    public static String unidentifiedMemberSummary(String storedSummary) {
        if (storedSummary == null) {
            return null;
        }
        Matcher placeholder = STORED_MEMBER.matcher(storedSummary);
        if (!placeholder.find() || placeholder.start() != 0) {
            return storedSummary;
        }
        return phrase(AuditEventType.STORED_MEMBER, true) + storedSummary.substring(placeholder.end());
    }

    /** One of this class's own phrases, capitalised when it starts the sentence. */
    private static String phrase(String phrase, boolean startsSentence) {
        return startsSentence ? capitalised(phrase) : phrase;
    }

    private static String capitalised(String text) {
        if (text.isEmpty()) {
            return text;
        }
        int first = text.codePointAt(0);
        return new StringBuilder(text.length()).appendCodePoint(Character.toTitleCase(first))
                .append(text, Character.charCount(first), text.length()).toString();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
