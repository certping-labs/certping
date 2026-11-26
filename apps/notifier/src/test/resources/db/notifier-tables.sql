-- Copyright Seaionl Inc. and CertPing contributors
-- SPDX-License-Identifier: Apache-2.0

-- The server's tables the notifier reads and writes (its Flyway owns them), as its
-- migrations leave them, without the foreign keys to tables the notifier never touches.
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    organization_id BIGINT,
    active BOOLEAN DEFAULT TRUE,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    organization_id BIGINT,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE user_roles (
    id BIGSERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users (id),
    role_id BIGINT NOT NULL REFERENCES roles (id),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE notification_records (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT,
    organization_id BIGINT,
    website_id VARCHAR(255),
    email VARCHAR(255),
    template_name VARCHAR(255),
    subject VARCHAR(255),
    sent_by VARCHAR(255),
    integration_type VARCHAR(255),
    status VARCHAR(255),
    payload_json TEXT,
    failure_reason VARCHAR(1000),
    sent_at TIMESTAMPTZ,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    request_id VARCHAR(255),
    correlation_id VARCHAR(255)
);

CREATE UNIQUE INDEX ux_notification_records_request_id ON notification_records (request_id) WHERE request_id IS NOT NULL;
