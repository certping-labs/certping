// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The audit trail: who did what to which
 * resource, when, from where, and with what outcome.
 *
 * <p>Rows live in {@code audit_events}, partitioned by month and append-only. They have two
 * visibilities: customer rows are a curated catalog of meaningful events ({@link
 * com.certmanagement.audit.AuditEventType}) an organization reads; internal rows are the platform's own
 * record. Ordinary page loads are not audit events; they belong in the application logs.
 *
 * <p>Build a row with {@link com.certmanagement.audit.AuditEvents} and hand it to {@link
 * com.certmanagement.audit.AuditRecorder}, which documents the three write paths. A failure carries an
 * {@link com.certmanagement.audit.AuditReason} code, never an exception or its text. The actor and
 * origin come from the request ({@link com.certmanagement.audit.AuditContext}) or, for jobs and
 * consumers, from an {@link com.certmanagement.audit.AuditScope}.
 *
 * <p>Customers read this table: {@link com.certmanagement.audit.AuditTrailReader} answers
 * {@code GET /api/v1/audit-logs} (90-day window, keyset cursor, capped count), and
 * {@link com.certmanagement.audit.AuditVisibilityPolicy} decides what features that are off hide (their
 * filter options, never their events). The same reader answers the Access view ({@code /access}: the
 * sensitive reads the list leaves out) and, for super admins, the platform view
 * ({@code GET /api/v1/admin/audit-logs}: internal rows, every organization, staff fields).
 * {@link com.certmanagement.audit.AuditTrailExporter} streams the exports, each recorded before any of its rows
 * is read.
 */
package com.certmanagement.audit;
