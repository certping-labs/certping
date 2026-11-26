// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.repository;

import com.certping.notification.model.NotificationRecord;
import com.certping.notification.model.NotificationStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface NotificationRepository extends JpaRepository<NotificationRecord, Long> {

    /** Look up an existing row by the publisher-supplied requestId. The
     *  notifier uses this as the natural key for find-or-insert on every
     *  attempt (initial + retries), so one logical notification = one row. */
    @Query("SELECT n FROM NotificationRecord n WHERE n.requestId = :requestId AND n.requestId IS NOT NULL")
    Optional<NotificationRecord> findByRequestId(@Param("requestId") String requestId);

    @Modifying
    @Query("update NotificationRecord r set r.status = :status, r.failureReason = :reason where r.id = :id")
    int updateStatusAndReasonById(@Param("id") Long id,
                                  @Param("status") NotificationStatus status,
                                  @Param("reason") String reason);

    @Modifying
    @Query("update NotificationRecord r set r.status = :status where r.id = :id")
    int updateStatusById(@Param("id") Long id,
                         @Param("status") NotificationStatus status);

    List<NotificationRecord> findByUserIdOrderByCreatedAtDesc(Long userId);

    Page<NotificationRecord> findByOrganizationIdOrderByCreatedAtDesc(Long organizationId, Pageable pageable);

    List<NotificationRecord> findByUserIdAndStatusOrderByCreatedAtDesc(Long userId, NotificationStatus status);

    Page<NotificationRecord> findByOrganizationIdAndStatusOrderByCreatedAtDesc(Long organizationId, NotificationStatus status, Pageable pageable);

    List<NotificationRecord> findAllByOrderByCreatedAtDesc();

    List<NotificationRecord> findByStatusOrderByCreatedAtDesc(NotificationStatus status);
}
