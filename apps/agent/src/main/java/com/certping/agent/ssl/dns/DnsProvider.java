// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

/**
 * A DNS host the agent writes domain-validation records to.
 *
 * Each implementation is constructed with its own parsed credentials,
 * not Spring-managed beans — instantiated per-message by DnsProviderFactory.
 */
public interface DnsProvider {

    /**
     * Adds a record of {@code type} at {@code recordName}.
     *
     * @param recordName full DNS name, e.g. {@code _acme-challenge.example.com}
     * @param value      the TXT content, or the CNAME target as a host name without a trailing dot
     * @return provider-specific record ID (used for deletion)
     */
    String addRecord(DnsRecordType type, String recordName, String value);

    /**
     * Deletes the record added by {@link #addRecord}.
     * Best-effort — implementations should not throw if record is already gone.
     *
     * @param recordName full DNS name
     * @param recordId   value returned by {@link #addRecord}
     */
    void deleteRecord(DnsRecordType type, String recordName, String recordId);

    default boolean supports(DnsRecordType type) {
        return true;
    }

    default String addTxtRecord(String recordName, String value) {
        return addRecord(DnsRecordType.TXT, recordName, value);
    }

    default void deleteTxtRecord(String recordName, String recordId) {
        deleteRecord(DnsRecordType.TXT, recordName, recordId);
    }
}
