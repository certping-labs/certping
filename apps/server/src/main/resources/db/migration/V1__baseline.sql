-- CertPing database baseline (0.1.0).
--
-- Creates the whole schema in one step, with the seed data a new installation needs: the four
-- system roles and their permissions, the global feature flags and the global settings.
-- It replaces the step-by-step migrations of the pre-release history; every later schema change is
-- a new migration (V2, V3, ...). Never edit this file once it has been applied anywhere: Flyway
-- checks each applied migration's checksum on start-up.

-- SQL function bodies may reference tables created further down.
SET LOCAL check_function_bodies = false;

-- ── Schema ──────────────────────────────────────────────────────────────────────

CREATE TYPE public.integration_provider AS ENUM (
    'SLACK',
    'TEAMS',
    'PAGERDUTY',
    'SERVICENOW_ITSM'
);

CREATE TYPE public.integration_status AS ENUM (
    'ACTIVE',
    'DISABLED'
);

CREATE FUNCTION public.audit_events_create_partition(month timestamp with time zone) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    first_day date := date_trunc('month', month AT TIME ZONE 'UTC')::date;
    part      text := format('audit_events_%s', to_char(first_day, 'YYYY_MM'));
    lower_at  timestamptz := first_day::timestamp AT TIME ZONE 'UTC';
    upper_at  timestamptz := (first_day + interval '1 month')::timestamp AT TIME ZONE 'UTC';
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('audit_events_partitions', 0));
    IF to_regclass(part) IS NOT NULL THEN
        RETURN NULL;
    END IF;
    EXECUTE format('CREATE TABLE %I (LIKE audit_events INCLUDING DEFAULTS INCLUDING CONSTRAINTS)', part);
    EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I CHECK (occurred_at >= %L AND occurred_at < %L)',
        part, part || '_bounds', lower_at, upper_at);
    EXECUTE format('ALTER TABLE audit_events ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L)',
        part, lower_at, upper_at);
    EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', part, part || '_bounds');
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION audit_events_refuse_change()',
        part || '_no_truncate', part);
    RETURN part;
END
$$;

CREATE FUNCTION public.audit_events_drop_partition(month date) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    first_day date := date_trunc('month', month)::date;
    part      text := 'audit_events_' || to_char(first_day, 'YYYY_MM');
BEGIN
    IF (first_day + interval '1 month')::timestamp AT TIME ZONE 'UTC'
            > (date_trunc('month', now() AT TIME ZONE 'UTC') - interval '6 months') AT TIME ZONE 'UTC' THEN
        RAISE EXCEPTION 'audit partition % ended later than six months ago', part
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('audit_events_partitions', 0));
    IF NOT EXISTS (SELECT 1 FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
                   WHERE i.inhparent = 'audit_events'::regclass AND c.relname = part) THEN
        RETURN NULL;
    END IF;
    EXECUTE format('DROP TABLE %I', part);
    RETURN part;
END
$$;

CREATE FUNCTION public.audit_events_drop_partitions_before(cutoff timestamp with time zone) RETURNS SETOF text
    LANGUAGE plpgsql
    AS $_$
DECLARE
    part text;
BEGIN
    IF cutoff > (date_trunc('month', now() AT TIME ZONE 'UTC') - interval '6 months') AT TIME ZONE 'UTC' THEN
        RAISE EXCEPTION 'audit retention cutoff % is later than six months ago', cutoff
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('audit_events_partitions', 0));
    FOR part IN
        SELECT c.relname::text FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'audit_events'::regclass
          AND c.relname ~ '^audit_events_[0-9]{4}_[0-9]{2}$'
          AND (to_date(substr(c.relname, 14), 'YYYY_MM') + interval '1 month')::timestamp AT TIME ZONE 'UTC' <= cutoff
        ORDER BY c.relname
    LOOP
        EXECUTE format('DROP TABLE %I', part);
        RETURN NEXT part;
    END LOOP;
END
$_$;

CREATE FUNCTION public.audit_events_refuse_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND current_setting('certping.audit_erasure', true) = 'on'
       AND NEW.actor_label IS NOT DISTINCT FROM 'Former member'
       AND to_jsonb(NEW) - 'actor_label' = to_jsonb(OLD) - 'actor_label' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE'
       AND current_setting('certping.audit_staff_fix', true) = 'on'
       AND OLD.actor_staff = false AND NEW.actor_staff = true
       AND to_jsonb(NEW) - 'actor_staff' = to_jsonb(OLD) - 'actor_staff' THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit_events is append-only: % refused', TG_OP USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TABLE public.agent_ca_status (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    agent_token_id bigint,
    ca_status jsonb NOT NULL,
    reported_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_ca_status_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_ca_status_id_seq OWNED BY public.agent_ca_status.id;

CREATE TABLE public.agent_deep_health_check_chunks (
    id bigint NOT NULL,
    deep_check_id character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    chunk_index integer NOT NULL,
    status character varying(32) NOT NULL,
    responded_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_deep_health_check_chunks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_deep_health_check_chunks_id_seq OWNED BY public.agent_deep_health_check_chunks.id;

CREATE TABLE public.agent_deep_health_check_metrics (
    id bigint NOT NULL,
    deep_check_id character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    chunk_index integer NOT NULL,
    metric_key character varying(256) NOT NULL,
    metric_name character varying(128) NOT NULL,
    metric_group character varying(64) NOT NULL,
    status character varying(16) NOT NULL,
    path character varying(1000),
    message text,
    details text,
    responded_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_deep_health_check_metrics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_deep_health_check_metrics_id_seq OWNED BY public.agent_deep_health_check_metrics.id;

CREATE TABLE public.agent_deep_health_checks (
    id bigint NOT NULL,
    deep_check_id character varying(100) NOT NULL,
    request_id character varying(100) NOT NULL,
    correlation_id character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    status character varying(32) DEFAULT 'PENDING'::character varying NOT NULL,
    expected_chunks integer DEFAULT 1 NOT NULL,
    received_chunks integer DEFAULT 0 NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    last_responded_at timestamp with time zone,
    error_code character varying(128),
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_deep_health_checks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_deep_health_checks_id_seq OWNED BY public.agent_deep_health_checks.id;

CREATE TABLE public.agent_health_status (
    organization_id bigint NOT NULL,
    overall_status character varying(32) DEFAULT 'UNKNOWN'::character varying NOT NULL,
    is_listening boolean,
    agent_checked_at timestamp with time zone,
    cms_received_at timestamp with time zone DEFAULT now() NOT NULL,
    last_error_code character varying(128),
    last_error_message text,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    version bigint DEFAULT 0 NOT NULL
);

CREATE TABLE public.agent_info (
    agent_token_id bigint NOT NULL,
    organization_id bigint NOT NULL,
    agent_info jsonb,
    last_heartbeat_at timestamp with time zone DEFAULT now() NOT NULL,
    reported_at timestamp with time zone
);

CREATE TABLE public.agent_result_receipts (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    agent_token_id bigint,
    message_id character varying(255),
    message_type character varying(64),
    request_id character varying(255),
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_result_receipts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_result_receipts_id_seq OWNED BY public.agent_result_receipts.id;

CREATE TABLE public.agent_tokens (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    name character varying(100) NOT NULL,
    token_hash character(64) NOT NULL,
    token_prefix character varying(16) NOT NULL,
    created_by character varying(255),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    expires_at timestamp with time zone
);

CREATE SEQUENCE public.agent_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_tokens_id_seq OWNED BY public.agent_tokens.id;

CREATE TABLE public.alert (
    id bigint NOT NULL,
    user_email character varying(255),
    user_id integer,
    organization_id bigint,
    alert_type character varying(50),
    status character varying(50),
    message text,
    error_detail text,
    error_code character varying(100),
    domain character varying(255),
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    severity character varying(20) DEFAULT 'CRITICAL'::character varying NOT NULL,
    unread boolean DEFAULT true NOT NULL,
    correlation_id character varying(100),
    CONSTRAINT chk_alert_exclusive_owner CHECK ((((user_id IS NOT NULL) AND (organization_id IS NULL)) OR ((user_id IS NULL) AND (organization_id IS NOT NULL))))
);

CREATE SEQUENCE public.alert_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.alert_id_seq OWNED BY public.alert.id;

CREATE TABLE public.audit_events (
    id bigint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    visibility text NOT NULL,
    event text,
    category text,
    feature_key text,
    organization_id bigint,
    actor_type text NOT NULL,
    actor_user_id integer,
    actor_label text,
    actor_job text,
    actor_staff boolean DEFAULT false NOT NULL,
    auth_method text,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id bigint,
    resource_ref text,
    resource_name text,
    outcome text NOT NULL,
    error_code text,
    summary text NOT NULL,
    details jsonb,
    ip_address text,
    user_agent text,
    request_id text,
    correlation_id text,
    trace_id text,
    CONSTRAINT audit_events_actor_type_check CHECK ((actor_type = ANY (ARRAY['USER'::text, 'API_TOKEN'::text, 'SYSTEM'::text, 'ANONYMOUS'::text]))),
    CONSTRAINT audit_events_customer_event_check CHECK (((visibility <> 'CUSTOMER'::text) OR ((event IS NOT NULL) AND (category IS NOT NULL)))),
    CONSTRAINT audit_events_details_check CHECK (((details IS NULL) OR (jsonb_typeof(details) = 'object'::text))),
    CONSTRAINT audit_events_outcome_check CHECK ((outcome = ANY (ARRAY['SUCCESS'::text, 'FAILURE'::text, 'PENDING'::text]))),
    CONSTRAINT audit_events_visibility_check CHECK ((visibility = ANY (ARRAY['CUSTOMER'::text, 'INTERNAL'::text])))
)
PARTITION BY RANGE (occurred_at);

CREATE TABLE public.audit_events_default (
    id bigint NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    visibility text NOT NULL,
    event text,
    category text,
    feature_key text,
    organization_id bigint,
    actor_type text NOT NULL,
    actor_user_id integer,
    actor_label text,
    actor_job text,
    actor_staff boolean DEFAULT false NOT NULL,
    auth_method text,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id bigint,
    resource_ref text,
    resource_name text,
    outcome text NOT NULL,
    error_code text,
    summary text NOT NULL,
    details jsonb,
    ip_address text,
    user_agent text,
    request_id text,
    correlation_id text,
    trace_id text,
    CONSTRAINT audit_events_actor_type_check CHECK ((actor_type = ANY (ARRAY['USER'::text, 'API_TOKEN'::text, 'SYSTEM'::text, 'ANONYMOUS'::text]))),
    CONSTRAINT audit_events_customer_event_check CHECK (((visibility <> 'CUSTOMER'::text) OR ((event IS NOT NULL) AND (category IS NOT NULL)))),
    CONSTRAINT audit_events_details_check CHECK (((details IS NULL) OR (jsonb_typeof(details) = 'object'::text))),
    CONSTRAINT audit_events_outcome_check CHECK ((outcome = ANY (ARRAY['SUCCESS'::text, 'FAILURE'::text, 'PENDING'::text]))),
    CONSTRAINT audit_events_visibility_check CHECK ((visibility = ANY (ARRAY['CUSTOMER'::text, 'INTERNAL'::text])))
);

ALTER TABLE public.audit_events ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.auth_refresh_tokens (
    id bigint NOT NULL,
    jti character varying(255) NOT NULL,
    token text NOT NULL,
    user_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    auth_method character varying(20) DEFAULT 'LOCAL'::character varying NOT NULL,
    CONSTRAINT auth_refresh_tokens_auth_method_check CHECK (((auth_method)::text = ANY ((ARRAY['LOCAL'::character varying, 'SOCIAL'::character varying, 'SSO'::character varying])::text[])))
);

CREATE SEQUENCE public.auth_refresh_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.auth_refresh_tokens_id_seq OWNED BY public.auth_refresh_tokens.id;

CREATE TABLE public.auth_revoked_access_tokens (
    id bigint NOT NULL,
    jti character varying(255) NOT NULL,
    user_id integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.auth_revoked_access_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.auth_revoked_access_tokens_id_seq OWNED BY public.auth_revoked_access_tokens.id;

CREATE TABLE public.auth_revoked_refresh_tokens (
    id bigint NOT NULL,
    token_id bigint NOT NULL,
    blacklisted_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.auth_revoked_refresh_tokens_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.auth_revoked_refresh_tokens_id_seq OWNED BY public.auth_revoked_refresh_tokens.id;

CREATE TABLE public.cert_deployment_config (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    user_domain_cert_id bigint NOT NULL,
    deployment_credential_id bigint NOT NULL,
    deployment_credential_xref character varying(100) NOT NULL,
    provider character varying(50) NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.cert_deployment_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cert_deployment_config_id_seq OWNED BY public.cert_deployment_config.id;

CREATE TABLE public.cert_issuance_retry_state (
    id bigint NOT NULL,
    certificate_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    workflow_type character varying(64) NOT NULL,
    status character varying(32) DEFAULT 'IN_PROGRESS'::character varying NOT NULL,
    attempt_count integer DEFAULT 1 NOT NULL,
    attempt_version integer DEFAULT 1 NOT NULL,
    max_attempts_snapshot integer NOT NULL,
    next_retry_at timestamp with time zone,
    last_attempt_at timestamp with time zone,
    response_deadline_at timestamp with time zone,
    last_failure_code character varying(100),
    last_failure_reason text,
    exhausted_at timestamp with time zone,
    claim_until timestamp with time zone,
    claimed_by character varying(128),
    version bigint DEFAULT 0 NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.cert_issuance_retry_state_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cert_issuance_retry_state_id_seq OWNED BY public.cert_issuance_retry_state.id;

CREATE TABLE public.cert_manual_issuance_state (
    id bigint NOT NULL,
    cert_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    acme_order_url text NOT NULL,
    acme_account_handle text NOT NULL,
    txt_records jsonb NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

CREATE SEQUENCE public.cert_manual_issuance_state_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cert_manual_issuance_state_id_seq OWNED BY public.cert_manual_issuance_state.id;

CREATE TABLE public.certificate_crypto_metadata (
    id bigint NOT NULL,
    certificate_xref character varying(100) NOT NULL,
    signature_algorithm_oid character varying(100),
    subject_dn text,
    common_name character varying(255),
    public_key_curve character varying(100),
    key_usage character varying(255),
    extended_key_usage text,
    subject_key_identifier character varying(200),
    authority_key_identifier character varying(200),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.certificate_crypto_metadata_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.certificate_crypto_metadata_id_seq OWNED BY public.certificate_crypto_metadata.id;

CREATE TABLE public.certificate_events (
    id bigint NOT NULL,
    certificate_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    event_type character varying(100) NOT NULL,
    from_status character varying(50),
    to_status character varying(50),
    request_id character varying(100),
    correlation_id character varying(100),
    user_id integer,
    reason character varying(50),
    details jsonb,
    source character varying(100),
    is_deleted boolean DEFAULT false NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.certificate_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.certificate_events_id_seq OWNED BY public.certificate_events.id;

CREATE TABLE public.certificates (
    id bigint NOT NULL,
    certificate_xref character varying(100) NOT NULL,
    user_domain_cert_id bigint NOT NULL,
    wildcard boolean DEFAULT false NOT NULL,
    san boolean DEFAULT false NOT NULL,
    san_domains text[] DEFAULT ARRAY[]::text[],
    ca_provider character varying(50) NOT NULL,
    status character varying(50) DEFAULT 'PENDING'::character varying NOT NULL,
    cert_secret_handle character varying(500),
    acme_account_handle character varying(500),
    ca_credential_handle character varying(500),
    issuer character varying(500),
    serial_number character varying(100),
    fingerprint_sha256 character varying(200),
    valid_from timestamp with time zone,
    valid_to timestamp with time zone,
    signature_algorithm character varying(100),
    public_key_algorithm character varying(50),
    key_size integer,
    cert_type character varying(20),
    last_error_code character varying(100),
    last_error_message text,
    last_error_at timestamp with time zone,
    last_alerted_at timestamp with time zone,
    target_resource_id character varying(1000),
    order_id character varying(64),
    special_certificate_type character varying(50),
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    requested_validity_days integer,
    correlation_id character varying(100),
    key_custody character varying(20) DEFAULT 'PLATFORM_HELD'::character varying NOT NULL,
    csr_pem text,
    ca_account_source character varying(20),
    ca_order_cost numeric(10,2),
    ca_order_currency character varying(3),
    expiry_alert_threshold_days integer,
    CONSTRAINT chk_certificates_ca_account_source CHECK (((ca_account_source)::text = ANY ((ARRAY['PLATFORM'::character varying, 'CUSTOMER'::character varying])::text[]))),
    CONSTRAINT chk_certificates_key_custody CHECK (((key_custody)::text = ANY ((ARRAY['PLATFORM_HELD'::character varying, 'CUSTOMER_HELD'::character varying])::text[])))
);

COMMENT ON COLUMN public.certificates.requested_validity_days IS 'Certificate validity in days as requested by the caller. Honored by DigiCert / GlobalSign; ignored for LETS_ENCRYPT (always 90d). NULL = agent default (90d). CA/Browser Forum caps: 200d from 2026-03-15, 100d from 2027-03-15, 47d from 2029-03-15 — each CA auto-truncates if requested above their current limit.';

COMMENT ON COLUMN public.certificates.expiry_alert_threshold_days IS 'Days-before-expiry threshold the last expiry alert was sent for; null until the first.';

CREATE SEQUENCE public.certificates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.certificates_id_seq OWNED BY public.certificates.id;

CREATE TABLE public.credential_references (
    id bigint NOT NULL,
    credential_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    provider character varying(50) NOT NULL,
    type character varying(50) NOT NULL,
    description character varying(500),
    status character varying(50) DEFAULT 'ACTIVE'::character varying NOT NULL,
    secret_handle character varying(500),
    last_error_message text,
    config jsonb,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_credential_references_secret_handle_ambient_auth CHECK (((secret_handle IS NOT NULL) OR (((provider)::text = 'KUBERNETES_SECRETS'::text) AND (COALESCE((config ->> 'authMethod'::text), ''::text) = 'SA_INCLUSTER'::text)) OR (((provider)::text = ANY ((ARRAY['AWS_ACM'::character varying, 'AWS_ALB'::character varying, 'AWS_NLB'::character varying, 'AWS_API_GW_REST'::character varying, 'AWS_API_GW_HTTP'::character varying, 'AWS_CLOUDFRONT'::character varying, 'AWS_ORGANIZATION'::character varying])::text[])) AND (COALESCE((config ->> 'authMode'::text), ''::text) = ANY (ARRAY['INSTANCE_PROFILE'::text, 'ASSUME_ROLE'::text]))) OR (((provider)::text = ANY ((ARRAY['AZURE_KV'::character varying, 'AZURE_APP_GW'::character varying, 'AZURE_APP_GW_CONTAINERS'::character varying, 'AZURE_AFD'::character varying])::text[])) AND (COALESCE((config ->> 'authMode'::text), ''::text) = 'WORKLOAD_IDENTITY'::text)) OR (((provider)::text = ANY ((ARRAY['GCP_CERT_MANAGER'::character varying, 'GCP_ALB'::character varying, 'GCP_PROXY_NLB'::character varying, 'GCP_API_GW'::character varying, 'GCP_CLOUD_CDN'::character varying])::text[])) AND (COALESCE((config ->> 'authMode'::text), ''::text) = 'WORKLOAD_IDENTITY'::text))))
);

CREATE SEQUENCE public.credential_references_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.credential_references_id_seq OWNED BY public.credential_references.id;

CREATE TABLE public.cron_runs (
    cron_name character varying(100) NOT NULL,
    active_pod_count integer DEFAULT 0 NOT NULL,
    last_activity_at timestamp with time zone NOT NULL,
    last_completed_at timestamp with time zone,
    continuation_due_at timestamp with time zone,
    CONSTRAINT chk_cron_runs_count_nonneg CHECK ((active_pod_count >= 0))
);

CREATE TABLE public.deployments (
    id bigint NOT NULL,
    request_id character varying(100) NOT NULL,
    correlation_id character varying(100),
    organization_id bigint NOT NULL,
    certificate_xref character varying(100) NOT NULL,
    user_domain_cert_id bigint,
    deployment_credential_xref character varying(100),
    target_type character varying(50) NOT NULL,
    flow_type character varying(50) NOT NULL,
    status character varying(50) NOT NULL,
    cert_secret_handle character varying(500),
    deployment_cred_handle character varying(500),
    target_resource_id character varying(1000),
    error_code character varying(100),
    error_detail text,
    requested_at timestamp with time zone NOT NULL,
    published_at timestamp with time zone,
    responded_at timestamp with time zone,
    completed_at timestamp with time zone,
    source character varying(100),
    metadata jsonb,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.deployments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.deployments_id_seq OWNED BY public.deployments.id;

CREATE TABLE public.discovered_cert (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    request_id character varying(100) NOT NULL,
    target_type character varying(50) NOT NULL,
    resource_id text NOT NULL,
    domain character varying(500),
    key_algorithm character varying(100),
    signature_algorithm character varying(100),
    not_before timestamp with time zone,
    not_after timestamp with time zone,
    issuer text,
    serial_number character varying(200),
    cert_status character varying(50),
    in_use_by text[],
    subject_dn text,
    san_domains text[],
    key_usage character varying(255),
    extended_key_usage text,
    cert_type character varying(50),
    managed boolean,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    provider_data jsonb,
    inventory_status character varying(20) DEFAULT 'UNKNOWN'::character varying NOT NULL,
    missing_since timestamp with time zone,
    CONSTRAINT chk_discovered_cert_inventory_status CHECK (((inventory_status)::text = ANY ((ARRAY['UNKNOWN'::character varying, 'PRESENT'::character varying, 'MISSING'::character varying])::text[])))
);

CREATE SEQUENCE public.discovered_cert_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.discovered_cert_id_seq OWNED BY public.discovered_cert.id;

CREATE TABLE public.discovered_cert_observation (
    id bigint NOT NULL,
    discovered_cert_id bigint NOT NULL,
    organization_id bigint NOT NULL,
    target_type character varying(50) NOT NULL,
    credential_xref character varying(255) NOT NULL,
    scope_key character varying(64) NOT NULL,
    status character varying(20) NOT NULL,
    last_seen_request_id character varying(100) NOT NULL,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    missing_since timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_discovered_cert_observation_status CHECK (((status)::text = ANY ((ARRAY['PRESENT'::character varying, 'MISSING'::character varying, 'OUT_OF_SCOPE'::character varying])::text[])))
);

CREATE SEQUENCE public.discovered_cert_observation_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.discovered_cert_observation_id_seq OWNED BY public.discovered_cert_observation.id;

CREATE TABLE public.discovery_config (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    target_type character varying(50) NOT NULL,
    credential_xref character varying(100) NOT NULL,
    credential_updated_at timestamp with time zone,
    scope_key character varying(64),
    last_request_id character varying(100),
    status character varying(30) DEFAULT 'READY'::character varying NOT NULL,
    status_message character varying(300) DEFAULT 'Discovery is ready to run.'::character varying NOT NULL,
    last_started_at timestamp with time zone,
    last_completed_at timestamp with time zone,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_discovery_config_status CHECK (((status)::text = ANY ((ARRAY['READY'::character varying, 'STARTED'::character varying, 'IN_PROGRESS'::character varying, 'COMPLETE'::character varying, 'PARTIAL'::character varying, 'FAILED'::character varying, 'CONFIG_REQUIRED'::character varying, 'CREDENTIAL_INVALID'::character varying, 'CANCELLED'::character varying])::text[])))
);

CREATE SEQUENCE public.discovery_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.discovery_config_id_seq OWNED BY public.discovery_config.id;

CREATE TABLE public.discovery_scan (
    request_id character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    target_type character varying(50) NOT NULL,
    credential_xref character varying(255) NOT NULL,
    scope_key character varying(64) NOT NULL,
    status character varying(20) NOT NULL,
    expected_batches integer,
    received_batch_indices integer[] DEFAULT '{}'::integer[] NOT NULL,
    received_cert_count integer DEFAULT 0 NOT NULL,
    completion_received boolean DEFAULT false NOT NULL,
    reported_total_certs integer,
    requested_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    finalized_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    failed_scopes text,
    CONSTRAINT chk_discovery_scan_expected_batches CHECK (((expected_batches IS NULL) OR (expected_batches >= 0))),
    CONSTRAINT chk_discovery_scan_received_cert_count CHECK ((received_cert_count >= 0)),
    CONSTRAINT chk_discovery_scan_reported_total_certs CHECK (((reported_total_certs IS NULL) OR (reported_total_certs >= 0))),
    CONSTRAINT chk_discovery_scan_status CHECK (((status)::text = ANY ((ARRAY['DISPATCHED'::character varying, 'RECEIVING'::character varying, 'COMPLETE'::character varying, 'PARTIAL'::character varying, 'FAILED'::character varying, 'CANCELLED'::character varying])::text[])))
);

CREATE TABLE public.domain_credential_config (
    id bigint NOT NULL,
    user_domain_cert_id bigint NOT NULL,
    dns_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    deployment_targets jsonb DEFAULT '[]'::jsonb NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.domain_credential_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.domain_credential_config_id_seq OWNED BY public.domain_credential_config.id;

CREATE TABLE public.feature_lifecycle_state (
    organization_id bigint NOT NULL,
    feature_key character varying(100) NOT NULL,
    platform_paused boolean DEFAULT false NOT NULL,
    transition_seq bigint DEFAULT 0 NOT NULL,
    notified_seq bigint DEFAULT 0 NOT NULL,
    pending_transition character varying(20),
    pending_items jsonb,
    pending_occurred_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    applied_transition_id bigint DEFAULT 0 NOT NULL,
    paused_claimed_seq bigint DEFAULT 0 NOT NULL,
    CONSTRAINT chk_feature_lifecycle_state_items CHECK (((pending_items IS NULL) OR (jsonb_typeof(pending_items) = 'array'::text))),
    CONSTRAINT chk_feature_lifecycle_state_seq CHECK ((notified_seq <= transition_seq)),
    CONSTRAINT chk_feature_lifecycle_state_transition CHECK (((pending_transition IS NULL) OR ((pending_transition)::text = ANY ((ARRAY['PAUSED'::character varying, 'RESUMED'::character varying])::text[]))))
);

CREATE TABLE public.feature_lifecycle_transition (
    id bigint NOT NULL,
    feature_key character varying(100) NOT NULL,
    scope character varying(20) NOT NULL,
    org_type character varying(10),
    organization_id bigint,
    before_enabled boolean,
    before_admin_locked boolean,
    after_enabled boolean,
    after_admin_locked boolean,
    actor_user_id integer,
    status character varying(20) DEFAULT 'PENDING'::character varying NOT NULL,
    cursor_phase character varying(10) DEFAULT 'PAUSE'::character varying NOT NULL,
    cursor_organization_id bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_feature_lifecycle_transition_phase CHECK (((cursor_phase)::text = ANY ((ARRAY['PAUSE'::character varying, 'RESUME'::character varying])::text[]))),
    CONSTRAINT chk_feature_lifecycle_transition_scope CHECK (((((scope)::text = 'GLOBAL'::text) AND (org_type IS NULL) AND (organization_id IS NULL)) OR (((scope)::text = 'ORG_TYPE'::text) AND (org_type IS NOT NULL) AND (organization_id IS NULL)) OR (((scope)::text = 'ORGANIZATION'::text) AND (org_type IS NULL) AND (organization_id IS NOT NULL)))),
    CONSTRAINT chk_feature_lifecycle_transition_status CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'COMPLETE'::character varying, 'SUPERSEDED'::character varying])::text[])))
);

CREATE SEQUENCE public.feature_lifecycle_transition_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.feature_lifecycle_transition_id_seq OWNED BY public.feature_lifecycle_transition.id;

CREATE TABLE public.global_feature_flags (
    id bigint NOT NULL,
    feature_key character varying(100) NOT NULL,
    display_name character varying(255) NOT NULL,
    description text,
    scope character varying(20) DEFAULT 'ORG'::character varying NOT NULL,
    category character varying(20) DEFAULT 'PLATFORM'::character varying NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    updated_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT global_feature_flags_category_check CHECK (((category)::text = ANY ((ARRAY['PLATFORM'::character varying, 'B2B'::character varying])::text[]))),
    CONSTRAINT global_feature_flags_scope_check CHECK (((scope)::text = ANY ((ARRAY['ORG'::character varying, 'PLATFORM'::character varying])::text[])))
);

CREATE SEQUENCE public.global_feature_flags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.global_feature_flags_id_seq OWNED BY public.global_feature_flags.id;

CREATE TABLE public.global_settings (
    key character varying(100) NOT NULL,
    value character varying(500) NOT NULL,
    description text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by bigint
);

CREATE TABLE public.incidents (
    id bigint NOT NULL,
    org_id bigint NOT NULL,
    actor_user_id bigint,
    source character varying(32) NOT NULL,
    provider character varying(32) NOT NULL,
    alert_id bigint,
    summary text NOT NULL,
    external_incident_id character varying(255),
    external_reference character varying(255) NOT NULL,
    external_url text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_incidents_alert_id_positive CHECK (((alert_id IS NULL) OR (alert_id > 0))),
    CONSTRAINT chk_incidents_provider CHECK (((provider)::text = ANY ((ARRAY['PAGERDUTY'::character varying, 'SERVICENOW_ITSM'::character varying])::text[]))),
    CONSTRAINT chk_incidents_source CHECK (((source)::text = ANY ((ARRAY['PUBLIC_API'::character varying, 'INTERNAL_API'::character varying])::text[])))
);

CREATE SEQUENCE public.incidents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.incidents_id_seq OWNED BY public.incidents.id;

CREATE TABLE public.installation (
    singleton boolean DEFAULT true NOT NULL,
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT installation_singleton_check CHECK (singleton)
);

CREATE TABLE public.integrations (
    id bigint NOT NULL,
    org_id bigint NOT NULL,
    provider public.integration_provider NOT NULL,
    status public.integration_status DEFAULT 'ACTIVE'::public.integration_status NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    secret_refs jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by bigint,
    updated_by bigint,
    deleted_by bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT chk_integrations_config_object CHECK ((jsonb_typeof(config) = 'object'::text)),
    CONSTRAINT chk_integrations_provider_payload CHECK ((((provider = ANY (ARRAY['SLACK'::public.integration_provider, 'TEAMS'::public.integration_provider])) AND (config ? 'webhook_host'::text) AND ((config - 'webhook_host'::text) = '{}'::jsonb) AND (secret_refs ? 'webhook_url'::text) AND ((secret_refs - 'webhook_url'::text) = '{}'::jsonb)) OR ((provider = 'PAGERDUTY'::public.integration_provider) AND (config = '{}'::jsonb) AND (secret_refs ? 'routing_key'::text) AND ((secret_refs - 'routing_key'::text) = '{}'::jsonb)) OR ((provider = 'SERVICENOW_ITSM'::public.integration_provider) AND (config ? 'instance_url'::text) AND (config ? 'instance_host'::text) AND ((((config - 'instance_url'::text) - 'instance_host'::text) = '{}'::jsonb) OR ((((config - 'instance_url'::text) - 'instance_host'::text) - 'oauth_scope'::text) = '{}'::jsonb)) AND (secret_refs ? 'client_id'::text) AND (secret_refs ? 'client_secret'::text) AND (((secret_refs - 'client_id'::text) - 'client_secret'::text) = '{}'::jsonb)))),
    CONSTRAINT chk_integrations_secret_refs_object CHECK ((jsonb_typeof(secret_refs) = 'object'::text))
);

CREATE SEQUENCE public.integrations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.integrations_id_seq OWNED BY public.integrations.id;

CREATE TABLE public.iot_ca_health_status (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    connector_id character varying(100) NOT NULL,
    ca_provider character varying(50) NOT NULL,
    enabled boolean NOT NULL,
    health_status character varying(30) NOT NULL,
    checked_at timestamp with time zone NOT NULL,
    responded_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    latency_ms bigint,
    endpoint character varying(1000),
    auth_method character varying(80),
    product_json jsonb,
    capabilities_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    profiles_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    issues_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    report_version integer NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_ca_health_latency CHECK (((latency_ms IS NULL) OR (latency_ms >= 0))),
    CONSTRAINT chk_iot_ca_health_report_version CHECK ((report_version > 0)),
    CONSTRAINT chk_iot_ca_health_status CHECK (((health_status)::text = ANY ((ARRAY['HEALTHY'::character varying, 'DEGRADED'::character varying, 'UNCONFIGURED'::character varying, 'UNREACHABLE'::character varying, 'UNAUTHORIZED'::character varying, 'ERROR'::character varying, 'UNKNOWN'::character varying])::text[])))
);

CREATE SEQUENCE public.iot_ca_health_status_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_ca_health_status_id_seq OWNED BY public.iot_ca_health_status.id;

CREATE TABLE public.iot_certificate_enrollment (
    id bigint NOT NULL,
    enrollment_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    device_source_id bigint NOT NULL,
    profile_id bigint,
    device_id bigint,
    endpoint_id character varying(100) NOT NULL,
    transaction_id character varying(255) NOT NULL,
    csr_fingerprint_sha256 character varying(64),
    asserted_source_device_id character varying(500),
    source_identifier_type character varying(30),
    source_identifier_assurance character varying(30),
    profile_resolution_status character varying(20) NOT NULL,
    enrollment_type character varying(20) NOT NULL,
    prior_certificate_issuer_dn character varying(2000),
    prior_certificate_serial_number character varying(160),
    device_match_status character varying(30) NOT NULL,
    status character varying(40) NOT NULL,
    failure_stage character varying(50),
    error_code character varying(100),
    error_message character varying(1000),
    retryable boolean DEFAULT false NOT NULL,
    requested_at timestamp with time zone NOT NULL,
    validated_at timestamp with time zone,
    issued_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_cert_enrollment_device_match CHECK (((device_match_status)::text = ANY ((ARRAY['NOT_ASSERTED'::character varying, 'MATCHED'::character varying, 'DEVICE_NOT_SYNCED'::character varying, 'IDENTIFIER_UNVERIFIED'::character varying, 'AMBIGUOUS'::character varying, 'INHERITED_FROM_RENEWAL'::character varying, 'RENEWAL_SOURCE_NOT_FOUND'::character varying])::text[]))),
    CONSTRAINT chk_iot_cert_enrollment_fingerprint CHECK (((csr_fingerprint_sha256 IS NULL) OR ((csr_fingerprint_sha256)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_iot_cert_enrollment_identifier_facts CHECK ((((asserted_source_device_id IS NULL) AND (source_identifier_type IS NULL) AND (source_identifier_assurance IS NULL)) OR ((asserted_source_device_id IS NOT NULL) AND ((source_identifier_type)::text = ANY ((ARRAY['MANAGED_DEVICE_ID'::character varying, 'ENTRA_DEVICE_ID'::character varying, 'ENTRA_OBJECT_ID'::character varying, 'UNKNOWN'::character varying])::text[])) AND ((source_identifier_assurance)::text = ANY ((ARRAY['MICROSOFT_VALIDATED'::character varying, 'ASSERTED'::character varying])::text[]))))),
    CONSTRAINT chk_iot_cert_enrollment_identity_provenance CHECK (((((enrollment_type)::text = 'INITIAL'::text) AND (prior_certificate_issuer_dn IS NULL) AND (prior_certificate_serial_number IS NULL) AND ((device_match_status)::text = ANY ((ARRAY['NOT_ASSERTED'::character varying, 'MATCHED'::character varying, 'DEVICE_NOT_SYNCED'::character varying, 'IDENTIFIER_UNVERIFIED'::character varying, 'AMBIGUOUS'::character varying])::text[]))) OR (((enrollment_type)::text = 'RENEWAL'::text) AND (asserted_source_device_id IS NULL) AND (prior_certificate_issuer_dn IS NOT NULL) AND (prior_certificate_serial_number IS NOT NULL) AND ((device_match_status)::text = ANY ((ARRAY['INHERITED_FROM_RENEWAL'::character varying, 'RENEWAL_SOURCE_NOT_FOUND'::character varying])::text[]))))),
    CONSTRAINT chk_iot_cert_enrollment_link_provenance CHECK ((((enrollment_type)::text <> 'INITIAL'::text) OR ((device_match_status)::text <> 'MATCHED'::text) OR ((COALESCE(source_identifier_assurance, ''::character varying))::text = 'MICROSOFT_VALIDATED'::text))),
    CONSTRAINT chk_iot_cert_enrollment_profile_link CHECK ((((profile_id IS NOT NULL) AND ((profile_resolution_status)::text = 'MATCHED'::text)) OR ((profile_id IS NULL) AND ((profile_resolution_status)::text <> 'MATCHED'::text)))),
    CONSTRAINT chk_iot_cert_enrollment_profile_resolution CHECK (((profile_resolution_status)::text = ANY ((ARRAY['MATCHED'::character varying, 'PENDING_SYNC'::character varying, 'NOT_FOUND'::character varying, 'AMBIGUOUS'::character varying])::text[]))),
    CONSTRAINT chk_iot_cert_enrollment_status CHECK (((status)::text = ANY ((ARRAY['RECEIVED'::character varying, 'VALIDATING'::character varying, 'SIGNING'::character varying, 'ISSUED_PENDING_NOTIFICATION'::character varying, 'ISSUED'::character varying, 'REJECTED'::character varying, 'FAILED'::character varying])::text[])))
);

COMMENT ON COLUMN public.iot_certificate_enrollment.endpoint_id IS 'Canonical SCEP route key: the device source connectionProfileRef, never a profileXref.';

CREATE SEQUENCE public.iot_certificate_enrollment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_certificate_enrollment_id_seq OWNED BY public.iot_certificate_enrollment.id;

CREATE TABLE public.iot_certificate_profile (
    id bigint NOT NULL,
    profile_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    device_source_id bigint NOT NULL,
    name character varying(200) NOT NULL,
    description character varying(1000),
    target_platform character varying(80) NOT NULL,
    target_variant character varying(80) DEFAULT 'STANDARD'::character varying NOT NULL,
    provider_profile_type character varying(150) NOT NULL,
    provider_profile_id character varying(500),
    provider_correlation_marker character varying(200),
    lifecycle_status character varying(30) DEFAULT 'DRAFT'::character varying NOT NULL,
    profile_origin character varying(30) NOT NULL,
    control_mode character varying(30) NOT NULL,
    profile_kind character varying(50) NOT NULL,
    enrollment_method character varying(50),
    desired_revision bigint,
    applied_revision bigint,
    latest_operation_xref character varying(100),
    latest_operation_started_at timestamp with time zone,
    latest_operation_completed_at timestamp with time zone,
    provider_sync_status character varying(30) DEFAULT 'NEVER'::character varying NOT NULL,
    provider_sync_error character varying(1000),
    last_provider_synced_at timestamp with time zone,
    created_by_user_id bigint,
    updated_by_user_id bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    last_provider_sync_xref character varying(100),
    CONSTRAINT chk_iot_profile_control_mode CHECK (((control_mode)::text = ANY ((ARRAY['CMS_MANAGED'::character varying, 'OBSERVED_ONLY'::character varying])::text[]))),
    CONSTRAINT chk_iot_profile_kind CHECK (((profile_kind)::text = ANY ((ARRAY['CERTIFICATE_ENROLLMENT'::character varying, 'TRUST_ANCHOR'::character varying, 'PROVISIONING_TEMPLATE'::character varying, 'ENROLLMENT_GROUP'::character varying])::text[]))),
    CONSTRAINT chk_iot_profile_lifecycle CHECK (((lifecycle_status)::text = ANY ((ARRAY['DRAFT'::character varying, 'ACTIVE'::character varying, 'ARCHIVED'::character varying])::text[]))),
    CONSTRAINT chk_iot_profile_origin CHECK (((profile_origin)::text = ANY ((ARRAY['CMS_CREATED'::character varying, 'PROVIDER_DISCOVERED'::character varying])::text[]))),
    CONSTRAINT chk_iot_profile_revision CHECK (((((control_mode)::text = 'CMS_MANAGED'::text) AND (desired_revision > 0) AND ((applied_revision IS NULL) OR (applied_revision > 0))) OR (((control_mode)::text = 'OBSERVED_ONLY'::text) AND (desired_revision IS NULL) AND (applied_revision IS NULL)))),
    CONSTRAINT chk_iot_profile_sync_status CHECK (((provider_sync_status)::text = ANY ((ARRAY['NEVER'::character varying, 'PENDING'::character varying, 'IN_SYNC'::character varying, 'FAILED'::character varying, 'DRIFTED'::character varying, 'NOT_FOUND'::character varying])::text[])))
);

CREATE TABLE public.iot_certificate_profile_configuration (
    profile_id bigint NOT NULL,
    organization_id bigint NOT NULL,
    device_source_id bigint NOT NULL,
    issuer_xref character varying(100),
    certificate_scope character varying(20),
    key_algorithm character varying(20),
    key_size integer,
    curve character varying(50),
    signature_hash character varying(30),
    subject_name_format character varying(1000),
    subject_alt_name_formats_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    extended_key_usages_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    key_usages_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    validity_value integer,
    validity_unit character varying(20),
    renewal_window_days integer,
    key_exportable boolean,
    provider_config_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_profile_certificate_scope CHECK (((certificate_scope IS NULL) OR ((certificate_scope)::text = ANY ((ARRAY['DEVICE'::character varying, 'USER'::character varying])::text[])))),
    CONSTRAINT chk_iot_profile_key_size CHECK (((key_size IS NULL) OR (key_size > 0))),
    CONSTRAINT chk_iot_profile_renewal_window CHECK (((renewal_window_days IS NULL) OR (renewal_window_days >= 0))),
    CONSTRAINT chk_iot_profile_validity CHECK ((((validity_value IS NULL) AND (validity_unit IS NULL)) OR ((validity_value > 0) AND ((validity_unit)::text = ANY ((ARRAY['DAYS'::character varying, 'MONTHS'::character varying, 'YEARS'::character varying])::text[])))))
);

CREATE SEQUENCE public.iot_certificate_profile_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_certificate_profile_id_seq OWNED BY public.iot_certificate_profile.id;

CREATE TABLE public.iot_certificate_profile_provider_snapshot (
    profile_id bigint NOT NULL,
    organization_id bigint NOT NULL,
    device_source_id bigint NOT NULL,
    provider_response_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    response_schema_version integer DEFAULT 1 NOT NULL,
    provider_version character varying(100),
    provider_last_modified_at timestamp with time zone,
    provider_observed_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_profile_snapshot_version CHECK ((response_schema_version > 0))
);

CREATE TABLE public.iot_certificate_revocation (
    id bigint NOT NULL,
    operation_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    certificate_id bigint,
    device_source_id bigint NOT NULL,
    source character varying(20) NOT NULL,
    idempotency_key character varying(100),
    intune_transaction_id character varying(100),
    request_context character varying(1000),
    request_context_hash character varying(64),
    reason character varying(40) NOT NULL,
    operator_note character varying(500),
    requested_by_user_id bigint,
    status character varying(30) NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone NOT NULL,
    dispatched_at timestamp with time zone,
    ca_observed_reason character varying(100),
    ca_observed_at timestamp with time zone,
    error_code character varying(100),
    error_message character varying(500),
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_certificate_revocation_attempts CHECK ((attempt_count >= 0)),
    CONSTRAINT chk_iot_certificate_revocation_context_hash CHECK (((request_context_hash IS NULL) OR ((request_context_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_iot_certificate_revocation_intune_fields CHECK (((((source)::text = 'INTUNE'::text) AND (intune_transaction_id IS NOT NULL) AND (request_context IS NOT NULL) AND (request_context_hash IS NOT NULL)) OR (((source)::text = 'UI'::text) AND (certificate_id IS NOT NULL) AND (intune_transaction_id IS NULL) AND (request_context IS NULL) AND (request_context_hash IS NULL)))),
    CONSTRAINT chk_iot_certificate_revocation_source CHECK (((source)::text = ANY ((ARRAY['UI'::character varying, 'INTUNE'::character varying])::text[]))),
    CONSTRAINT chk_iot_certificate_revocation_status CHECK (((status)::text = ANY ((ARRAY['PENDING'::character varying, 'DISPATCHED'::character varying, 'CONFIRMED'::character varying, 'FAILED'::character varying, 'OUTCOME_UNKNOWN'::character varying])::text[])))
);

CREATE SEQUENCE public.iot_certificate_revocation_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_certificate_revocation_id_seq OWNED BY public.iot_certificate_revocation.id;

CREATE TABLE public.iot_device (
    id bigint NOT NULL,
    device_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    device_source_id bigint NOT NULL,
    source_device_id character varying(500) NOT NULL,
    source_identifiers_json jsonb,
    device_class character varying(30) NOT NULL,
    serial_number character varying(255),
    device_name character varying(255),
    manufacturer character varying(200),
    model character varying(200),
    ownership character varying(30),
    status character varying(50) DEFAULT 'REGISTERED'::character varying NOT NULL,
    registered_at timestamp with time zone,
    last_seen_in_source_at timestamp with time zone,
    decommissioned_at timestamp with time zone,
    provider_attributes_json jsonb,
    provider_attributes_schema_version integer DEFAULT 1 NOT NULL,
    provider_attributes_updated_at timestamp with time zone,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT chk_iot_device_class CHECK (((device_class)::text = ANY ((ARRAY['MANAGED_ENDPOINT'::character varying, 'CONNECTED_THING'::character varying, 'INDUSTRIAL_ASSET'::character varying])::text[]))),
    CONSTRAINT chk_iot_device_ownership CHECK (((ownership IS NULL) OR ((ownership)::text = ANY ((ARRAY['COMPANY'::character varying, 'PERSONAL'::character varying, 'UNKNOWN'::character varying])::text[])))),
    CONSTRAINT chk_iot_device_status CHECK (((status)::text = ANY ((ARRAY['REGISTERED'::character varying, 'ORPHANED'::character varying, 'DECOMMISSIONED'::character varying])::text[]))),
    CONSTRAINT chk_iot_provider_attributes_version CHECK ((provider_attributes_schema_version > 0))
);

CREATE TABLE public.iot_device_certificate (
    id bigint NOT NULL,
    certificate_xref character varying(100) NOT NULL,
    enrollment_id bigint NOT NULL,
    organization_id bigint NOT NULL,
    device_source_id bigint NOT NULL,
    profile_id bigint,
    device_id bigint,
    ca_provider character varying(50) NOT NULL,
    issuer_xref character varying(100),
    ca_name character varying(255),
    ca_end_entity_name character varying(255),
    ca_provisioner_name character varying(255),
    issuer_dn character varying(2000) NOT NULL,
    serial_number character varying(160) NOT NULL,
    subject_dn character varying(2000) NOT NULL,
    common_name character varying(500),
    subject_alt_names_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    certificate_scope character varying(20),
    fingerprint_sha1 character varying(40) NOT NULL,
    fingerprint_sha256 character varying(64) NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    valid_to timestamp with time zone NOT NULL,
    signature_algorithm character varying(100),
    signature_algorithm_oid character varying(100),
    public_key_algorithm character varying(30),
    key_size integer,
    public_key_curve character varying(100),
    key_usage_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    extended_key_usage_oids_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    certificate_policy_oids_json jsonb DEFAULT '[]'::jsonb NOT NULL,
    subject_key_identifier character varying(255),
    authority_key_identifier character varying(255),
    is_ca boolean DEFAULT false NOT NULL,
    status character varying(40) NOT NULL,
    renewal_state character varying(20) DEFAULT 'NONE'::character varying NOT NULL,
    nudge_attempts integer DEFAULT 0 NOT NULL,
    last_nudged_at timestamp with time zone,
    last_nudge_request_id character varying(100),
    last_nudge_outcome character varying(40),
    renewal_due_at timestamp with time zone,
    issued_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_device_certificate_fingerprint CHECK ((((fingerprint_sha1)::text ~ '^[0-9a-f]{40}$'::text) AND ((fingerprint_sha256)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_iot_device_certificate_key_size CHECK (((key_size IS NULL) OR (key_size > 0))),
    CONSTRAINT chk_iot_device_certificate_nudge_attempts CHECK ((nudge_attempts >= 0)),
    CONSTRAINT chk_iot_device_certificate_renewal_state CHECK (((renewal_state)::text = ANY ((ARRAY['NONE'::character varying, 'NUDGING'::character varying, 'RENEWED'::character varying])::text[]))),
    CONSTRAINT chk_iot_device_certificate_scope CHECK (((certificate_scope IS NULL) OR ((certificate_scope)::text = ANY ((ARRAY['DEVICE'::character varying, 'USER'::character varying])::text[])))),
    CONSTRAINT chk_iot_device_certificate_status CHECK (((status)::text = ANY ((ARRAY['ISSUED_PENDING_NOTIFICATION'::character varying, 'ISSUED'::character varying, 'REVOCATION_PENDING'::character varying, 'REVOCATION_DISPATCHED'::character varying, 'REVOKED'::character varying, 'REVOCATION_FAILED'::character varying, 'REVOCATION_OUTCOME_UNKNOWN'::character varying])::text[]))),
    CONSTRAINT chk_iot_device_certificate_validity CHECK ((valid_to > valid_from))
);

CREATE SEQUENCE public.iot_device_certificate_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_device_certificate_id_seq OWNED BY public.iot_device_certificate.id;

CREATE TABLE public.iot_device_connected_thing (
    device_id bigint NOT NULL,
    attestation_type character varying(30),
    hub_or_account_ref character varying(255),
    thing_type character varying(200),
    form_factor character varying(20),
    connectivity_state character varying(50),
    last_connected_at timestamp with time zone,
    custom_attributes jsonb,
    CONSTRAINT chk_iot_thing_form_factor CHECK (((form_factor IS NULL) OR ((form_factor)::text = ANY ((ARRAY['MCU'::character varying, 'MPU'::character varying, 'GATEWAY'::character varying])::text[]))))
);

CREATE TABLE public.iot_device_endpoint_posture (
    device_id bigint NOT NULL,
    operating_system character varying(50),
    os_version character varying(100),
    compliance_state character varying(30),
    compliance_state_raw character varying(100),
    is_encrypted boolean,
    is_supervised boolean,
    jailbroken_state character varying(20),
    management_agent character varying(50),
    enrollment_type character varying(100),
    mdm_enrolled_at timestamp with time zone,
    mdm_last_sync_at timestamp with time zone,
    vendor_attributes jsonb,
    CONSTRAINT chk_iot_posture_compliance CHECK (((compliance_state IS NULL) OR ((compliance_state)::text = ANY ((ARRAY['COMPLIANT'::character varying, 'NON_COMPLIANT'::character varying, 'IN_GRACE'::character varying, 'UNKNOWN'::character varying])::text[]))))
);

CREATE TABLE public.iot_device_event (
    id bigint NOT NULL,
    event_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    device_id bigint,
    certificate_enrollment_id bigint,
    event_type character varying(50) NOT NULL,
    event_status character varying(50),
    event_message character varying(1000),
    actor_user_id bigint,
    actor_source character varying(50),
    detail_json jsonb,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    correlation_id character varying(100),
    dedupe_key character varying(255),
    CONSTRAINT chk_iot_device_event_actor CHECK (((actor_source IS NULL) OR ((actor_source)::text = ANY ((ARRAY['SYSTEM'::character varying, 'UI'::character varying, 'API'::character varying, 'AGENT'::character varying, 'SYNC'::character varying, 'PLATFORM'::character varying, 'DEVICE'::character varying])::text[])))),
    CONSTRAINT chk_iot_device_event_owner CHECK (((device_id IS NOT NULL) OR (certificate_enrollment_id IS NOT NULL))),
    CONSTRAINT chk_iot_device_event_type CHECK (((event_type)::text = ANY ((ARRAY['DEVICE_DISCOVERED'::character varying, 'DEVICE_UPDATED'::character varying, 'DEVICE_ORPHANED'::character varying, 'DEVICE_RESTORED'::character varying, 'DEVICE_ARCHIVED'::character varying, 'COMPLIANCE_CHANGED'::character varying, 'OWNER_CHANGED'::character varying, 'DECOMMISSIONED'::character varying, 'CERTIFICATE_REQUESTED'::character varying, 'CHALLENGE_VALIDATED'::character varying, 'CHALLENGE_REJECTED'::character varying, 'CA_ISSUANCE_STARTED'::character varying, 'CERTIFICATE_ISSUED'::character varying, 'INTUNE_NOTIFICATION_SUCCEEDED'::character varying, 'CERTIFICATE_ENROLLMENT_FAILED'::character varying, 'CERTIFICATE_DEVICE_MATCHED'::character varying, 'CERTIFICATE_DEVICE_UNMATCHED'::character varying, 'CERTIFICATE_PROFILE_MATCHED'::character varying, 'CERTIFICATE_PROFILE_UNMATCHED'::character varying, 'CERTIFICATE_NUDGE_REQUESTED'::character varying, 'CERTIFICATE_NUDGE_SENT'::character varying, 'CERTIFICATE_NUDGE_FAILED'::character varying, 'CERTIFICATE_RENEWED'::character varying, 'CERTIFICATE_REVOCATION_REQUESTED'::character varying, 'CERTIFICATE_REVOCATION_DISPATCHED'::character varying, 'CERTIFICATE_REVOCATION_CONFIRMED'::character varying, 'CERTIFICATE_REVOCATION_FAILED'::character varying, 'CERTIFICATE_REVOCATION_OUTCOME_UNKNOWN'::character varying, 'INTUNE_REVOCATION_REQUEST_DOWNLOADED'::character varying, 'INTUNE_REVOCATION_RESULT_UPLOADED'::character varying])::text[])))
);

CREATE SEQUENCE public.iot_device_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_device_event_id_seq OWNED BY public.iot_device_event.id;

CREATE SEQUENCE public.iot_device_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_device_id_seq OWNED BY public.iot_device.id;

CREATE TABLE public.iot_device_owner (
    device_id bigint NOT NULL,
    organization_id bigint NOT NULL,
    owner_upn character varying(320),
    owner_email character varying(320),
    owner_display_name character varying(255),
    is_deleted boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.iot_device_source (
    id bigint NOT NULL,
    source_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    provider character varying(50) NOT NULL,
    source_category character varying(50) NOT NULL,
    connection_profile_ref character varying(100) NOT NULL,
    display_name character varying(200) NOT NULL,
    description character varying(500),
    configuration_metadata_json jsonb,
    sync_enabled boolean DEFAULT false NOT NULL,
    status character varying(50) DEFAULT 'ACTIVE'::character varying NOT NULL,
    first_advertised_at timestamp with time zone NOT NULL,
    last_advertised_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_device_source_category CHECK (((source_category)::text = ANY ((ARRAY['ENDPOINT_MANAGEMENT'::character varying, 'IOT_REGISTRY'::character varying, 'MANUAL'::character varying])::text[]))),
    CONSTRAINT chk_iot_device_source_provider CHECK (((provider)::text = ANY ((ARRAY['INTUNE'::character varying, 'JAMF'::character varying, 'WORKSPACE_ONE'::character varying, 'AWS_IOT'::character varying, 'AZURE_IOT'::character varying, 'GCP_IOT'::character varying, 'CISCO'::character varying, 'LWM2M'::character varying, 'MANUAL'::character varying])::text[]))),
    CONSTRAINT chk_iot_device_source_status CHECK (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'DISABLED'::character varying])::text[])))
);

CREATE TABLE public.iot_device_source_event (
    id bigint NOT NULL,
    event_xref character varying(100) NOT NULL,
    organization_id bigint NOT NULL,
    device_source_id bigint NOT NULL,
    event_type character varying(50) NOT NULL,
    event_status character varying(50),
    detail_json jsonb,
    occurred_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    correlation_id character varying(100),
    dedupe_key character varying(200) NOT NULL,
    CONSTRAINT chk_iot_source_event_type CHECK (((event_type)::text = ANY ((ARRAY['SOURCE_ADVERTISED'::character varying, 'HEALTH_REPORTED'::character varying, 'SYNC_ENABLED'::character varying, 'SYNC_DISABLED'::character varying, 'SYNC_REQUESTED'::character varying, 'SYNC_STARTED'::character varying, 'SYNC_PART_RECEIVED'::character varying, 'SYNC_COMPLETED'::character varying, 'SYNC_FAILED'::character varying, 'PROFILE_CREATED'::character varying, 'PROFILE_UPDATE_REQUESTED'::character varying, 'PROFILE_UPDATE_CONFIRMED'::character varying, 'PROFILE_APPLY_SUCCEEDED'::character varying, 'PROFILE_APPLY_FAILED'::character varying, 'PROFILE_DISCOVERED'::character varying, 'PROFILE_DRIFTED'::character varying, 'PROFILE_ARCHIVED'::character varying, 'PROFILE_SYNC_REQUESTED'::character varying, 'PROFILE_SYNC_STARTED'::character varying, 'PROFILE_SYNC_PART_RECEIVED'::character varying, 'PROFILE_SYNC_COMPLETION_RECEIVED'::character varying, 'PROFILE_SYNC_COMPLETED'::character varying, 'PROFILE_SYNC_FAILED'::character varying])::text[])))
);

CREATE SEQUENCE public.iot_device_source_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_device_source_event_id_seq OWNED BY public.iot_device_source_event.id;

CREATE TABLE public.iot_device_source_health_status (
    device_source_id bigint NOT NULL,
    last_health_xref character varying(100) NOT NULL,
    health_status character varying(30) NOT NULL,
    provider_status character varying(100),
    status_message character varying(1000),
    health_metadata_json jsonb,
    agent_instance_xref character varying(100) NOT NULL,
    agent_sequence bigint NOT NULL,
    check_started_at timestamp with time zone NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    published_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone NOT NULL,
    response_time_ms bigint,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_source_health_response_time CHECK (((response_time_ms IS NULL) OR (response_time_ms >= 0))),
    CONSTRAINT chk_iot_source_health_sequence CHECK ((agent_sequence >= 0)),
    CONSTRAINT chk_iot_source_health_status CHECK (((health_status)::text = ANY ((ARRAY['HEALTHY'::character varying, 'DEGRADED'::character varying, 'UNHEALTHY'::character varying, 'UNKNOWN'::character varying])::text[])))
);

CREATE SEQUENCE public.iot_device_source_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_device_source_id_seq OWNED BY public.iot_device_source.id;

CREATE TABLE public.iot_device_source_sync_state (
    device_source_id bigint NOT NULL,
    sync_xref character varying(100) NOT NULL,
    sync_status character varying(30) NOT NULL,
    sync_mode character varying(30) DEFAULT 'FULL'::character varying NOT NULL,
    requested_by_user_id bigint,
    requested_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    expected_device_count integer,
    processed_device_count integer DEFAULT 0 NOT NULL,
    failed_device_count integer DEFAULT 0 NOT NULL,
    expected_batch_count integer,
    processed_batch_count integer DEFAULT 0 NOT NULL,
    received_batches_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    completion_received boolean DEFAULT false NOT NULL,
    last_error character varying(1000),
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_source_sync_counts CHECK (((processed_device_count >= 0) AND (failed_device_count >= 0) AND (processed_batch_count >= 0) AND ((expected_device_count IS NULL) OR (expected_device_count >= 0)) AND ((expected_batch_count IS NULL) OR (expected_batch_count >= 0)))),
    CONSTRAINT chk_iot_source_sync_mode CHECK (((sync_mode)::text = 'FULL'::text)),
    CONSTRAINT chk_iot_source_sync_status CHECK (((sync_status)::text = ANY ((ARRAY['PENDING'::character varying, 'RUNNING'::character varying, 'OK'::character varying, 'PARTIAL'::character varying, 'FAILED'::character varying])::text[])))
);

CREATE TABLE public.iot_intune_revocation_poll_state (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    device_source_id bigint NOT NULL,
    transaction_id character varying(100),
    status character varying(30) NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone NOT NULL,
    requested_at timestamp with time zone,
    dispatched_at timestamp with time zone,
    downloaded_at timestamp with time zone,
    uploaded_at timestamp with time zone,
    last_error_code character varying(100),
    last_error_message character varying(500),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_iot_intune_revocation_poll_attempts CHECK ((attempt_count >= 0)),
    CONSTRAINT chk_iot_intune_revocation_poll_status CHECK (((status)::text = ANY ((ARRAY['IDLE'::character varying, 'PENDING_POLL'::character varying, 'POLL_DISPATCHED'::character varying, 'PROCESSING'::character varying, 'PENDING_UPLOAD'::character varying, 'UPLOAD_DISPATCHED'::character varying, 'FAILED'::character varying])::text[]))),
    CONSTRAINT chk_iot_intune_revocation_poll_transaction CHECK (((((status)::text = 'IDLE'::text) AND (transaction_id IS NULL)) OR (((status)::text <> 'IDLE'::text) AND (transaction_id IS NOT NULL))))
);

CREATE SEQUENCE public.iot_intune_revocation_poll_state_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.iot_intune_revocation_poll_state_id_seq OWNED BY public.iot_intune_revocation_poll_state.id;

CREATE TABLE public.message_queue (
    id bigint NOT NULL,
    channel character varying(200) NOT NULL,
    message_id character varying(200),
    body text NOT NULL,
    properties jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(16) DEFAULT 'READY'::character varying NOT NULL,
    delivery_count integer DEFAULT 0 NOT NULL,
    enqueued_at timestamp with time zone DEFAULT now() NOT NULL,
    available_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    lock_token uuid,
    locked_until timestamp with time zone,
    dead_reason character varying(200),
    dead_description text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    CONSTRAINT message_queue_status_check CHECK (((status)::text = ANY ((ARRAY['READY'::character varying, 'LEASED'::character varying, 'DEAD'::character varying])::text[])))
);

CREATE SEQUENCE public.message_queue_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.message_queue_id_seq OWNED BY public.message_queue.id;

CREATE TABLE public.notification_records (
    id bigint NOT NULL,
    user_id bigint,
    organization_id bigint,
    website_id character varying(255),
    email character varying(255),
    template_name character varying(255),
    subject character varying(255),
    sent_by character varying(255),
    integration_type character varying(255),
    status character varying(255),
    payload_json text,
    failure_reason character varying(1000),
    sent_at timestamp with time zone,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    request_id character varying(255),
    correlation_id character varying(255)
);

CREATE SEQUENCE public.notification_records_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.notification_records_id_seq OWNED BY public.notification_records.id;

CREATE TABLE public.org_type_feature_flags (
    id bigint NOT NULL,
    org_type character varying(10) NOT NULL,
    feature_key character varying(100) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    updated_by_user_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_org_type_feature_flags_org_type CHECK (((org_type)::text = 'B2B'::text))
);

CREATE SEQUENCE public.org_type_feature_flags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.org_type_feature_flags_id_seq OWNED BY public.org_type_feature_flags.id;

CREATE TABLE public.organization_feature_flags (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    feature_key character varying(100) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    updated_by_user_id integer,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    admin_locked boolean DEFAULT false NOT NULL
);

CREATE SEQUENCE public.organization_feature_flags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.organization_feature_flags_id_seq OWNED BY public.organization_feature_flags.id;

CREATE TABLE public.organizations (
    id bigint NOT NULL,
    name character varying(255) NOT NULL,
    domain character varying(255) NOT NULL,
    slug character varying(255) NOT NULL,
    active boolean DEFAULT true NOT NULL,
    org_type character varying(10) DEFAULT 'B2B'::character varying NOT NULL,
    kv_base_uri character varying(500),
    agent_heartbeat_cadence_minutes integer DEFAULT 5 NOT NULL,
    soft_delete_retention_days integer,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    muted_notification_categories character varying(64)[] DEFAULT '{}'::character varying[] NOT NULL,
    CONSTRAINT chk_organizations_agent_heartbeat_cadence CHECK (((agent_heartbeat_cadence_minutes >= 1) AND (agent_heartbeat_cadence_minutes <= 60))),
    CONSTRAINT chk_organizations_org_type CHECK (((org_type)::text = 'B2B'::text))
);

CREATE SEQUENCE public.organizations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.organizations_id_seq OWNED BY public.organizations.id;

CREATE TABLE public.permissions (
    id bigint NOT NULL,
    name character varying(100) NOT NULL,
    resource character varying(100) NOT NULL,
    action character varying(50) NOT NULL,
    description text,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE SEQUENCE public.permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.permissions_id_seq OWNED BY public.permissions.id;

CREATE TABLE public.queue_alert_state (
    id bigint NOT NULL,
    entity_name character varying(512) NOT NULL,
    metric character varying(16) NOT NULL,
    alert_state character varying(16) DEFAULT 'OK'::character varying NOT NULL,
    last_value bigint DEFAULT 0 NOT NULL,
    consecutive_breaches integer DEFAULT 0 NOT NULL,
    last_alerted_at timestamp with time zone,
    recovered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT queue_alert_state_alert_state_check CHECK (((alert_state)::text = ANY ((ARRAY['OK'::character varying, 'ALERTING'::character varying])::text[]))),
    CONSTRAINT queue_alert_state_metric_check CHECK (((metric)::text = ANY ((ARRAY['ACTIVE'::character varying, 'DLQ'::character varying, 'SCAN_FAILURES'::character varying])::text[])))
);

CREATE SEQUENCE public.queue_alert_state_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.queue_alert_state_id_seq OWNED BY public.queue_alert_state.id;

CREATE TABLE public.renewal_schedule (
    id bigint NOT NULL,
    certificate_xref character varying(100) NOT NULL,
    domain_credential_config_id bigint NOT NULL,
    valid_to timestamp with time zone NOT NULL,
    renewal_eligible_at timestamp with time zone NOT NULL,
    renewal_window_days integer DEFAULT 30 NOT NULL,
    ca_provider character varying(50) NOT NULL,
    acme_account_handle character varying(500),
    ca_credential_handle character varying(500),
    cert_secret_handle character varying(500),
    enabled boolean DEFAULT false NOT NULL,
    last_renewal_at timestamp with time zone,
    last_renewal_status character varying(50),
    next_attempt_at timestamp with time zone,
    order_id character varying(64),
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    consecutive_failures integer DEFAULT 0 NOT NULL,
    CONSTRAINT chk_renewal_schedule_consecutive_failures CHECK ((consecutive_failures >= 0))
);

CREATE SEQUENCE public.renewal_schedule_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.renewal_schedule_id_seq OWNED BY public.renewal_schedule.id;

CREATE TABLE public.role_permissions (
    id bigint NOT NULL,
    role_id bigint NOT NULL,
    permission_id bigint NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE SEQUENCE public.role_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.role_permissions_id_seq OWNED BY public.role_permissions.id;

CREATE TABLE public.roles (
    id bigint NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    organization_id bigint,
    is_system_role boolean DEFAULT false,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT chk_roles_scope_consistency CHECK ((((is_system_role = true) AND (organization_id IS NULL)) OR ((is_system_role = false) AND (organization_id IS NOT NULL))))
);

CREATE SEQUENCE public.roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;

CREATE TABLE public.spring_session (
    primary_id character(36) NOT NULL,
    session_id character(36) NOT NULL,
    creation_time bigint NOT NULL,
    last_access_time bigint NOT NULL,
    max_inactive_interval integer NOT NULL,
    expiry_time bigint NOT NULL,
    principal_name character varying(100)
);

CREATE TABLE public.spring_session_attributes (
    session_primary_id character(36) NOT NULL,
    attribute_name character varying(200) NOT NULL,
    attribute_bytes bytea NOT NULL
);

CREATE TABLE public.user_domain_certificate (
    id bigint NOT NULL,
    organization_id bigint NOT NULL,
    domain character varying(255) NOT NULL,
    user_id integer,
    is_deleted boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.user_domain_certificate_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.user_domain_certificate_id_seq OWNED BY public.user_domain_certificate.id;

CREATE TABLE public.user_mfa (
    user_id integer NOT NULL,
    secret_sealed text NOT NULL,
    confirmed_at timestamp with time zone,
    last_used_step bigint,
    recovery_code_hashes text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

COMMENT ON TABLE public.user_mfa IS 'TOTP second factor for local accounts; the secret is sealed with the password pepper.';

COMMENT ON COLUMN public.user_mfa.last_used_step IS 'The last 30-second step a code was accepted for, so a code cannot be replayed.';

COMMENT ON COLUMN public.user_mfa.recovery_code_hashes IS 'Comma-separated SHA-256 hex digests of unused recovery codes.';

CREATE TABLE public.user_permissions (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    permission_id bigint NOT NULL,
    granted_by integer,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.user_permissions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.user_permissions_id_seq OWNED BY public.user_permissions.id;

CREATE TABLE public.user_roles (
    id bigint NOT NULL,
    user_id integer NOT NULL,
    role_id bigint NOT NULL,
    assigned_by integer,
    is_deleted boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE SEQUENCE public.user_roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.user_roles_id_seq OWNED BY public.user_roles.id;

CREATE TABLE public.users (
    id integer NOT NULL,
    email character varying(255) NOT NULL,
    organization_id bigint,
    idp_user_id character varying(255),
    username character varying(100),
    password_hash character varying(255),
    display_name character varying(255),
    must_change_password boolean DEFAULT false,
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp with time zone,
    auth_method character varying(20) DEFAULT 'SSO'::character varying,
    active boolean DEFAULT true,
    is_deleted boolean DEFAULT false NOT NULL,
    last_login_at timestamp with time zone,
    provisioned_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    disabled_at timestamp with time zone,
    tokens_valid_after timestamp with time zone,
    CONSTRAINT users_auth_method_check CHECK (((auth_method)::text = ANY ((ARRAY['LOCAL'::character varying, 'SSO'::character varying])::text[])))
);

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;

ALTER TABLE ONLY public.audit_events ATTACH PARTITION public.audit_events_default DEFAULT;

ALTER TABLE ONLY public.agent_ca_status ALTER COLUMN id SET DEFAULT nextval('public.agent_ca_status_id_seq'::regclass);

ALTER TABLE ONLY public.agent_deep_health_check_chunks ALTER COLUMN id SET DEFAULT nextval('public.agent_deep_health_check_chunks_id_seq'::regclass);

ALTER TABLE ONLY public.agent_deep_health_check_metrics ALTER COLUMN id SET DEFAULT nextval('public.agent_deep_health_check_metrics_id_seq'::regclass);

ALTER TABLE ONLY public.agent_deep_health_checks ALTER COLUMN id SET DEFAULT nextval('public.agent_deep_health_checks_id_seq'::regclass);

ALTER TABLE ONLY public.agent_result_receipts ALTER COLUMN id SET DEFAULT nextval('public.agent_result_receipts_id_seq'::regclass);

ALTER TABLE ONLY public.agent_tokens ALTER COLUMN id SET DEFAULT nextval('public.agent_tokens_id_seq'::regclass);

ALTER TABLE ONLY public.alert ALTER COLUMN id SET DEFAULT nextval('public.alert_id_seq'::regclass);

ALTER TABLE ONLY public.auth_refresh_tokens ALTER COLUMN id SET DEFAULT nextval('public.auth_refresh_tokens_id_seq'::regclass);

ALTER TABLE ONLY public.auth_revoked_access_tokens ALTER COLUMN id SET DEFAULT nextval('public.auth_revoked_access_tokens_id_seq'::regclass);

ALTER TABLE ONLY public.auth_revoked_refresh_tokens ALTER COLUMN id SET DEFAULT nextval('public.auth_revoked_refresh_tokens_id_seq'::regclass);

ALTER TABLE ONLY public.cert_deployment_config ALTER COLUMN id SET DEFAULT nextval('public.cert_deployment_config_id_seq'::regclass);

ALTER TABLE ONLY public.cert_issuance_retry_state ALTER COLUMN id SET DEFAULT nextval('public.cert_issuance_retry_state_id_seq'::regclass);

ALTER TABLE ONLY public.cert_manual_issuance_state ALTER COLUMN id SET DEFAULT nextval('public.cert_manual_issuance_state_id_seq'::regclass);

ALTER TABLE ONLY public.certificate_crypto_metadata ALTER COLUMN id SET DEFAULT nextval('public.certificate_crypto_metadata_id_seq'::regclass);

ALTER TABLE ONLY public.certificate_events ALTER COLUMN id SET DEFAULT nextval('public.certificate_events_id_seq'::regclass);

ALTER TABLE ONLY public.certificates ALTER COLUMN id SET DEFAULT nextval('public.certificates_id_seq'::regclass);

ALTER TABLE ONLY public.credential_references ALTER COLUMN id SET DEFAULT nextval('public.credential_references_id_seq'::regclass);

ALTER TABLE ONLY public.deployments ALTER COLUMN id SET DEFAULT nextval('public.deployments_id_seq'::regclass);

ALTER TABLE ONLY public.discovered_cert ALTER COLUMN id SET DEFAULT nextval('public.discovered_cert_id_seq'::regclass);

ALTER TABLE ONLY public.discovered_cert_observation ALTER COLUMN id SET DEFAULT nextval('public.discovered_cert_observation_id_seq'::regclass);

ALTER TABLE ONLY public.discovery_config ALTER COLUMN id SET DEFAULT nextval('public.discovery_config_id_seq'::regclass);

ALTER TABLE ONLY public.domain_credential_config ALTER COLUMN id SET DEFAULT nextval('public.domain_credential_config_id_seq'::regclass);

ALTER TABLE ONLY public.feature_lifecycle_transition ALTER COLUMN id SET DEFAULT nextval('public.feature_lifecycle_transition_id_seq'::regclass);

ALTER TABLE ONLY public.global_feature_flags ALTER COLUMN id SET DEFAULT nextval('public.global_feature_flags_id_seq'::regclass);

ALTER TABLE ONLY public.incidents ALTER COLUMN id SET DEFAULT nextval('public.incidents_id_seq'::regclass);

ALTER TABLE ONLY public.integrations ALTER COLUMN id SET DEFAULT nextval('public.integrations_id_seq'::regclass);

ALTER TABLE ONLY public.iot_ca_health_status ALTER COLUMN id SET DEFAULT nextval('public.iot_ca_health_status_id_seq'::regclass);

ALTER TABLE ONLY public.iot_certificate_enrollment ALTER COLUMN id SET DEFAULT nextval('public.iot_certificate_enrollment_id_seq'::regclass);

ALTER TABLE ONLY public.iot_certificate_profile ALTER COLUMN id SET DEFAULT nextval('public.iot_certificate_profile_id_seq'::regclass);

ALTER TABLE ONLY public.iot_certificate_revocation ALTER COLUMN id SET DEFAULT nextval('public.iot_certificate_revocation_id_seq'::regclass);

ALTER TABLE ONLY public.iot_device ALTER COLUMN id SET DEFAULT nextval('public.iot_device_id_seq'::regclass);

ALTER TABLE ONLY public.iot_device_certificate ALTER COLUMN id SET DEFAULT nextval('public.iot_device_certificate_id_seq'::regclass);

ALTER TABLE ONLY public.iot_device_event ALTER COLUMN id SET DEFAULT nextval('public.iot_device_event_id_seq'::regclass);

ALTER TABLE ONLY public.iot_device_source ALTER COLUMN id SET DEFAULT nextval('public.iot_device_source_id_seq'::regclass);

ALTER TABLE ONLY public.iot_device_source_event ALTER COLUMN id SET DEFAULT nextval('public.iot_device_source_event_id_seq'::regclass);

ALTER TABLE ONLY public.iot_intune_revocation_poll_state ALTER COLUMN id SET DEFAULT nextval('public.iot_intune_revocation_poll_state_id_seq'::regclass);

ALTER TABLE ONLY public.message_queue ALTER COLUMN id SET DEFAULT nextval('public.message_queue_id_seq'::regclass);

ALTER TABLE ONLY public.notification_records ALTER COLUMN id SET DEFAULT nextval('public.notification_records_id_seq'::regclass);

ALTER TABLE ONLY public.org_type_feature_flags ALTER COLUMN id SET DEFAULT nextval('public.org_type_feature_flags_id_seq'::regclass);

ALTER TABLE ONLY public.organization_feature_flags ALTER COLUMN id SET DEFAULT nextval('public.organization_feature_flags_id_seq'::regclass);

ALTER TABLE ONLY public.organizations ALTER COLUMN id SET DEFAULT nextval('public.organizations_id_seq'::regclass);

ALTER TABLE ONLY public.permissions ALTER COLUMN id SET DEFAULT nextval('public.permissions_id_seq'::regclass);

ALTER TABLE ONLY public.queue_alert_state ALTER COLUMN id SET DEFAULT nextval('public.queue_alert_state_id_seq'::regclass);

ALTER TABLE ONLY public.renewal_schedule ALTER COLUMN id SET DEFAULT nextval('public.renewal_schedule_id_seq'::regclass);

ALTER TABLE ONLY public.role_permissions ALTER COLUMN id SET DEFAULT nextval('public.role_permissions_id_seq'::regclass);

ALTER TABLE ONLY public.roles ALTER COLUMN id SET DEFAULT nextval('public.roles_id_seq'::regclass);

ALTER TABLE ONLY public.user_domain_certificate ALTER COLUMN id SET DEFAULT nextval('public.user_domain_certificate_id_seq'::regclass);

ALTER TABLE ONLY public.user_permissions ALTER COLUMN id SET DEFAULT nextval('public.user_permissions_id_seq'::regclass);

ALTER TABLE ONLY public.user_roles ALTER COLUMN id SET DEFAULT nextval('public.user_roles_id_seq'::regclass);

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);

ALTER TABLE ONLY public.agent_ca_status
    ADD CONSTRAINT agent_ca_status_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_deep_health_check_chunks
    ADD CONSTRAINT agent_deep_health_check_chunks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_deep_health_check_metrics
    ADD CONSTRAINT agent_deep_health_check_metrics_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_deep_health_checks
    ADD CONSTRAINT agent_deep_health_checks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_health_status
    ADD CONSTRAINT agent_health_status_pkey PRIMARY KEY (organization_id);

ALTER TABLE ONLY public.agent_info
    ADD CONSTRAINT agent_info_pkey PRIMARY KEY (agent_token_id);

ALTER TABLE ONLY public.agent_result_receipts
    ADD CONSTRAINT agent_result_receipts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_tokens
    ADD CONSTRAINT agent_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_tokens
    ADD CONSTRAINT agent_tokens_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.alert
    ADD CONSTRAINT alert_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id, occurred_at);

ALTER TABLE ONLY public.audit_events_default
    ADD CONSTRAINT audit_events_default_pkey PRIMARY KEY (id, occurred_at);

ALTER TABLE ONLY public.auth_refresh_tokens
    ADD CONSTRAINT auth_refresh_tokens_jti_key UNIQUE (jti);

ALTER TABLE ONLY public.auth_refresh_tokens
    ADD CONSTRAINT auth_refresh_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.auth_revoked_access_tokens
    ADD CONSTRAINT auth_revoked_access_tokens_jti_key UNIQUE (jti);

ALTER TABLE ONLY public.auth_revoked_access_tokens
    ADD CONSTRAINT auth_revoked_access_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.auth_revoked_refresh_tokens
    ADD CONSTRAINT auth_revoked_refresh_tokens_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.auth_revoked_refresh_tokens
    ADD CONSTRAINT auth_revoked_refresh_tokens_token_id_key UNIQUE (token_id);

ALTER TABLE ONLY public.cert_deployment_config
    ADD CONSTRAINT cert_deployment_config_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cert_issuance_retry_state
    ADD CONSTRAINT cert_issuance_retry_state_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cert_manual_issuance_state
    ADD CONSTRAINT cert_manual_issuance_state_cert_xref_key UNIQUE (cert_xref);

ALTER TABLE ONLY public.cert_manual_issuance_state
    ADD CONSTRAINT cert_manual_issuance_state_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.certificate_crypto_metadata
    ADD CONSTRAINT certificate_crypto_metadata_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.certificate_events
    ADD CONSTRAINT certificate_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_certificate_xref_key UNIQUE (certificate_xref);

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.credential_references
    ADD CONSTRAINT credential_references_credential_xref_key UNIQUE (credential_xref);

ALTER TABLE ONLY public.credential_references
    ADD CONSTRAINT credential_references_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cron_runs
    ADD CONSTRAINT cron_runs_pkey PRIMARY KEY (cron_name);

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT deployments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.deployments
    ADD CONSTRAINT deployments_request_id_key UNIQUE (request_id);

ALTER TABLE ONLY public.discovered_cert_observation
    ADD CONSTRAINT discovered_cert_observation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.discovered_cert
    ADD CONSTRAINT discovered_cert_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.discovery_config
    ADD CONSTRAINT discovery_config_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.discovery_scan
    ADD CONSTRAINT discovery_scan_pkey PRIMARY KEY (request_id);

ALTER TABLE ONLY public.domain_credential_config
    ADD CONSTRAINT domain_credential_config_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.domain_credential_config
    ADD CONSTRAINT domain_credential_config_user_domain_cert_id_key UNIQUE (user_domain_cert_id);

ALTER TABLE ONLY public.feature_lifecycle_state
    ADD CONSTRAINT feature_lifecycle_state_pkey PRIMARY KEY (organization_id, feature_key);

ALTER TABLE ONLY public.feature_lifecycle_transition
    ADD CONSTRAINT feature_lifecycle_transition_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.global_feature_flags
    ADD CONSTRAINT global_feature_flags_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.global_settings
    ADD CONSTRAINT global_settings_pkey PRIMARY KEY (key);

ALTER TABLE ONLY public.incidents
    ADD CONSTRAINT incidents_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.installation
    ADD CONSTRAINT installation_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_ca_health_status
    ADD CONSTRAINT iot_ca_health_status_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT iot_certificate_enrollment_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_certificate_profile_configuration
    ADD CONSTRAINT iot_certificate_profile_configuration_pkey PRIMARY KEY (profile_id);

ALTER TABLE ONLY public.iot_certificate_profile
    ADD CONSTRAINT iot_certificate_profile_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_certificate_profile_provider_snapshot
    ADD CONSTRAINT iot_certificate_profile_provider_snapshot_pkey PRIMARY KEY (profile_id);

ALTER TABLE ONLY public.iot_certificate_revocation
    ADD CONSTRAINT iot_certificate_revocation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT iot_device_certificate_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_device_connected_thing
    ADD CONSTRAINT iot_device_connected_thing_pkey PRIMARY KEY (device_id);

ALTER TABLE ONLY public.iot_device_endpoint_posture
    ADD CONSTRAINT iot_device_endpoint_posture_pkey PRIMARY KEY (device_id);

ALTER TABLE ONLY public.iot_device_event
    ADD CONSTRAINT iot_device_event_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_device_owner
    ADD CONSTRAINT iot_device_owner_pkey PRIMARY KEY (device_id);

ALTER TABLE ONLY public.iot_device
    ADD CONSTRAINT iot_device_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_device_source_event
    ADD CONSTRAINT iot_device_source_event_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_device_source_health_status
    ADD CONSTRAINT iot_device_source_health_status_pkey PRIMARY KEY (device_source_id);

ALTER TABLE ONLY public.iot_device_source
    ADD CONSTRAINT iot_device_source_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.iot_device_source_sync_state
    ADD CONSTRAINT iot_device_source_sync_state_pkey PRIMARY KEY (device_source_id);

ALTER TABLE ONLY public.iot_intune_revocation_poll_state
    ADD CONSTRAINT iot_intune_revocation_poll_state_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.message_queue
    ADD CONSTRAINT message_queue_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.notification_records
    ADD CONSTRAINT notification_records_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.org_type_feature_flags
    ADD CONSTRAINT org_type_feature_flags_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organization_feature_flags
    ADD CONSTRAINT organization_feature_flags_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_name_key UNIQUE (name);

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.queue_alert_state
    ADD CONSTRAINT queue_alert_state_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.renewal_schedule
    ADD CONSTRAINT renewal_schedule_certificate_xref_key UNIQUE (certificate_xref);

ALTER TABLE ONLY public.renewal_schedule
    ADD CONSTRAINT renewal_schedule_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.spring_session_attributes
    ADD CONSTRAINT spring_session_attributes_pk PRIMARY KEY (session_primary_id, attribute_name);

ALTER TABLE ONLY public.spring_session
    ADD CONSTRAINT spring_session_pk PRIMARY KEY (primary_id);

ALTER TABLE ONLY public.agent_deep_health_checks
    ADD CONSTRAINT uk_adch_deep_check_id UNIQUE (deep_check_id);

ALTER TABLE ONLY public.agent_deep_health_checks
    ADD CONSTRAINT uk_adch_request_id UNIQUE (request_id);

ALTER TABLE ONLY public.certificate_crypto_metadata
    ADD CONSTRAINT uk_cert_crypto_metadata_xref UNIQUE (certificate_xref);

ALTER TABLE ONLY public.global_feature_flags
    ADD CONSTRAINT uk_gff_feature_key UNIQUE (feature_key);

ALTER TABLE ONLY public.iot_ca_health_status
    ADD CONSTRAINT uk_iot_ca_health_connector UNIQUE (organization_id, connector_id);

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT uk_iot_cert_enrollment_org UNIQUE (id, organization_id);

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT uk_iot_cert_enrollment_source_scope UNIQUE (id, organization_id, device_source_id);

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT uk_iot_cert_enrollment_transaction UNIQUE (organization_id, device_source_id, transaction_id);

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT uk_iot_cert_enrollment_xref UNIQUE (enrollment_xref);

ALTER TABLE ONLY public.iot_certificate_profile
    ADD CONSTRAINT uk_iot_certificate_profile_scope UNIQUE (id, organization_id, device_source_id);

ALTER TABLE ONLY public.iot_certificate_profile
    ADD CONSTRAINT uk_iot_certificate_profile_xref UNIQUE (profile_xref);

ALTER TABLE ONLY public.iot_certificate_revocation
    ADD CONSTRAINT uk_iot_certificate_revocation_xref UNIQUE (operation_xref);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT uk_iot_device_certificate_ca_serial UNIQUE (organization_id, ca_provider, issuer_dn, serial_number);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT uk_iot_device_certificate_enrollment UNIQUE (enrollment_id);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT uk_iot_device_certificate_fingerprint UNIQUE (fingerprint_sha256);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT uk_iot_device_certificate_org UNIQUE (id, organization_id);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT uk_iot_device_certificate_xref UNIQUE (certificate_xref);

ALTER TABLE ONLY public.iot_device_event
    ADD CONSTRAINT uk_iot_device_event_xref UNIQUE (event_xref);

ALTER TABLE ONLY public.iot_device
    ADD CONSTRAINT uk_iot_device_org UNIQUE (id, organization_id);

ALTER TABLE ONLY public.iot_device
    ADD CONSTRAINT uk_iot_device_scope UNIQUE (id, organization_id, device_source_id);

ALTER TABLE ONLY public.iot_device
    ADD CONSTRAINT uk_iot_device_source_id UNIQUE (device_source_id, source_device_id);

ALTER TABLE ONLY public.iot_device_source
    ADD CONSTRAINT uk_iot_device_source_id_org UNIQUE (id, organization_id);

ALTER TABLE ONLY public.iot_device_source
    ADD CONSTRAINT uk_iot_device_source_profile UNIQUE (organization_id, connection_profile_ref);

ALTER TABLE ONLY public.iot_device_source
    ADD CONSTRAINT uk_iot_device_source_xref UNIQUE (source_xref);

ALTER TABLE ONLY public.iot_device
    ADD CONSTRAINT uk_iot_device_xref UNIQUE (device_xref);

ALTER TABLE ONLY public.iot_intune_revocation_poll_state
    ADD CONSTRAINT uk_iot_intune_revocation_poll_source UNIQUE (device_source_id);

ALTER TABLE ONLY public.iot_device_source_event
    ADD CONSTRAINT uk_iot_source_event_dedupe UNIQUE (device_source_id, dedupe_key);

ALTER TABLE ONLY public.iot_device_source_event
    ADD CONSTRAINT uk_iot_source_event_xref UNIQUE (event_xref);

ALTER TABLE ONLY public.iot_device_source_health_status
    ADD CONSTRAINT uk_iot_source_health_xref UNIQUE (last_health_xref);

ALTER TABLE ONLY public.iot_device_source_sync_state
    ADD CONSTRAINT uk_iot_source_sync_xref UNIQUE (sync_xref);

ALTER TABLE ONLY public.org_type_feature_flags
    ADD CONSTRAINT uk_otff_type_feature UNIQUE (org_type, feature_key);

ALTER TABLE ONLY public.discovered_cert_observation
    ADD CONSTRAINT uq_discovered_cert_observation_scope UNIQUE (discovered_cert_id, scope_key);

ALTER TABLE ONLY public.discovered_cert
    ADD CONSTRAINT uq_discovered_cert_org_resource UNIQUE (organization_id, resource_id);

ALTER TABLE ONLY public.queue_alert_state
    ADD CONSTRAINT uq_queue_alert_state UNIQUE (entity_name, metric);

ALTER TABLE ONLY public.user_domain_certificate
    ADD CONSTRAINT user_domain_certificate_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_mfa
    ADD CONSTRAINT user_mfa_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT user_permissions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

CREATE INDEX audit_events_actor_idx ON ONLY public.audit_events USING btree (actor_user_id) WHERE (actor_user_id IS NOT NULL);

CREATE INDEX audit_events_correlation_idx ON ONLY public.audit_events USING btree (correlation_id) WHERE (correlation_id IS NOT NULL);

CREATE INDEX audit_events_customer_actor_idx ON ONLY public.audit_events USING btree (organization_id, actor_user_id, occurred_at DESC, id DESC) WHERE (visibility = 'CUSTOMER'::text);

CREATE INDEX audit_events_customer_category_idx ON ONLY public.audit_events USING btree (organization_id, category, occurred_at DESC, id DESC) WHERE (visibility = 'CUSTOMER'::text);

CREATE INDEX audit_events_customer_idx ON ONLY public.audit_events USING btree (organization_id, occurred_at DESC, id DESC) WHERE (visibility = 'CUSTOMER'::text);

CREATE INDEX audit_events_default_actor_user_id_idx ON public.audit_events_default USING btree (actor_user_id) WHERE (actor_user_id IS NOT NULL);

CREATE INDEX audit_events_default_correlation_id_idx ON public.audit_events_default USING btree (correlation_id) WHERE (correlation_id IS NOT NULL);

CREATE INDEX audit_events_occurred_idx ON ONLY public.audit_events USING btree (occurred_at DESC, id DESC);

CREATE INDEX audit_events_default_occurred_at_id_idx ON public.audit_events_default USING btree (occurred_at DESC, id DESC);

CREATE INDEX audit_events_default_organization_id_actor_user_id_occurred_idx ON public.audit_events_default USING btree (organization_id, actor_user_id, occurred_at DESC, id DESC) WHERE (visibility = 'CUSTOMER'::text);

CREATE INDEX audit_events_default_organization_id_category_occurred_at_i_idx ON public.audit_events_default USING btree (organization_id, category, occurred_at DESC, id DESC) WHERE (visibility = 'CUSTOMER'::text);

CREATE INDEX audit_events_default_organization_id_occurred_at_id_idx ON public.audit_events_default USING btree (organization_id, occurred_at DESC, id DESC) WHERE (visibility = 'CUSTOMER'::text);

CREATE INDEX audit_events_org_idx ON ONLY public.audit_events USING btree (organization_id, occurred_at DESC, id DESC);

CREATE INDEX audit_events_default_organization_id_occurred_at_id_idx1 ON public.audit_events_default USING btree (organization_id, occurred_at DESC, id DESC);

CREATE INDEX audit_events_target_idx ON ONLY public.audit_events USING btree (organization_id, resource_type, resource_ref) WHERE (resource_ref IS NOT NULL);

CREATE INDEX audit_events_default_organization_id_resource_type_resource_idx ON public.audit_events_default USING btree (organization_id, resource_type, resource_ref) WHERE (resource_ref IS NOT NULL);

CREATE INDEX audit_events_request_idx ON ONLY public.audit_events USING btree (request_id) WHERE (request_id IS NOT NULL);

CREATE INDEX audit_events_default_request_id_idx ON public.audit_events_default USING btree (request_id) WHERE (request_id IS NOT NULL);

CREATE INDEX idx_agent_health_status_cms_received_at ON public.agent_health_status USING btree (cms_received_at DESC);

CREATE INDEX idx_agent_health_status_overall_status ON public.agent_health_status USING btree (overall_status);

CREATE INDEX idx_alert_organization_id ON public.alert USING btree (organization_id);

CREATE INDEX idx_alert_user_id ON public.alert USING btree (user_id);

CREATE INDEX idx_auth_refresh_tokens_exp ON public.auth_refresh_tokens USING btree (expires_at);

CREATE INDEX idx_auth_refresh_tokens_jti ON public.auth_refresh_tokens USING btree (jti);

CREATE INDEX idx_auth_refresh_tokens_method ON public.auth_refresh_tokens USING btree (auth_method);

CREATE INDEX idx_auth_refresh_tokens_user ON public.auth_refresh_tokens USING btree (user_id);

CREATE INDEX idx_cert_crypto_metadata_xref ON public.certificate_crypto_metadata USING btree (certificate_xref);

CREATE INDEX idx_cert_events_correlation_id ON public.certificate_events USING btree (correlation_id);

CREATE INDEX idx_cert_events_organization_time ON public.certificate_events USING btree (organization_id, occurred_at DESC);

CREATE INDEX idx_cert_events_request_id ON public.certificate_events USING btree (request_id);

CREATE INDEX idx_cert_events_revocation_reason_occurred_at ON public.certificate_events USING btree (reason, occurred_at DESC) WHERE ((event_type)::text = ANY ((ARRAY['REVOCATION_REQUESTED'::character varying, 'REVOCATION_SUCCESS'::character varying, 'REVOCATION_FAILED'::character varying])::text[]));

CREATE INDEX idx_cert_events_type_time ON public.certificate_events USING btree (event_type, occurred_at DESC);

CREATE INDEX idx_cert_events_user_id_occurred_at ON public.certificate_events USING btree (user_id, occurred_at DESC) WHERE (user_id IS NOT NULL);

CREATE INDEX idx_cert_events_xref ON public.certificate_events USING btree (certificate_xref);

CREATE INDEX idx_cert_user_domain_cert_id ON public.certificates USING btree (user_domain_cert_id);

CREATE INDEX idx_certificates_expiry_alert ON public.certificates USING btree (valid_to, last_alerted_at) WHERE (((status)::text = 'ACTIVE'::text) AND (deleted_at IS NULL) AND (valid_to IS NOT NULL));

CREATE INDEX idx_certificates_status ON public.certificates USING btree (status) WHERE (deleted_at IS NULL);

CREATE INDEX idx_certificates_valid_to ON public.certificates USING btree (valid_to) WHERE (((status)::text = ANY ((ARRAY['ACTIVE'::character varying, 'RENEWING'::character varying])::text[])) AND (deleted_at IS NULL));

CREATE INDEX idx_certificates_xref ON public.certificates USING btree (certificate_xref);

CREATE INDEX idx_cirs_cert_workflow ON public.cert_issuance_retry_state USING btree (certificate_xref, workflow_type);

CREATE INDEX idx_cirs_due ON public.cert_issuance_retry_state USING btree (next_retry_at, response_deadline_at) WHERE ((status)::text = 'IN_PROGRESS'::text);

CREATE INDEX idx_cmis_cert_xref ON public.cert_manual_issuance_state USING btree (cert_xref);

CREATE INDEX idx_credential_references_active ON public.credential_references USING btree (organization_id, type) WHERE ((status)::text = 'ACTIVE'::text);

CREATE INDEX idx_credential_references_organization ON public.credential_references USING btree (organization_id);

CREATE INDEX idx_deployments_cert_created_at ON public.deployments USING btree (certificate_xref, created_at DESC);

CREATE INDEX idx_deployments_correlation_id ON public.deployments USING btree (correlation_id);

CREATE INDEX idx_deployments_organization_created_at ON public.deployments USING btree (organization_id, created_at DESC);

CREATE INDEX idx_deployments_organization_udc ON public.deployments USING btree (organization_id, user_domain_cert_id);

CREATE INDEX idx_deployments_status_created_at ON public.deployments USING btree (status, created_at DESC);

CREATE INDEX idx_discovered_cert_not_after ON public.discovered_cert USING btree (organization_id, not_after);

CREATE INDEX idx_discovered_cert_observation_cert_status ON public.discovered_cert_observation USING btree (discovered_cert_id, status);

CREATE INDEX idx_discovered_cert_observation_credential_scope ON public.discovered_cert_observation USING btree (organization_id, target_type, credential_xref, scope_key);

CREATE INDEX idx_discovered_cert_observation_scope_status ON public.discovered_cert_observation USING btree (scope_key, status);

CREATE INDEX idx_discovered_cert_org_id ON public.discovered_cert USING btree (organization_id);

CREATE INDEX idx_discovered_cert_org_status ON public.discovered_cert USING btree (organization_id, cert_status);

CREATE INDEX idx_discovered_cert_org_targettype ON public.discovered_cert USING btree (organization_id, target_type);

CREATE INDEX idx_discovery_config_last_request ON public.discovery_config USING btree (last_request_id) WHERE ((is_deleted = false) AND (last_request_id IS NOT NULL));

CREATE INDEX idx_discovery_config_org_target_credential ON public.discovery_config USING btree (organization_id, target_type, credential_xref) WHERE (is_deleted = false);

CREATE INDEX idx_discovery_config_org_target_status ON public.discovery_config USING btree (organization_id, target_type, status) WHERE (is_deleted = false);

CREATE INDEX idx_discovery_config_org_updated ON public.discovery_config USING btree (organization_id, updated_at DESC) WHERE (is_deleted = false);

CREATE INDEX idx_discovery_scan_org_target_requested ON public.discovery_scan USING btree (organization_id, target_type, requested_at DESC);

CREATE INDEX idx_discovery_scan_running_org ON public.discovery_scan USING btree (organization_id) WHERE ((status)::text = ANY ((ARRAY['DISPATCHED'::character varying, 'RECEIVING'::character varying])::text[]));

CREATE INDEX idx_feature_lifecycle_state_paused ON public.feature_lifecycle_state USING btree (feature_key, organization_id) WHERE (platform_paused = true);

CREATE INDEX idx_feature_lifecycle_state_unnotified ON public.feature_lifecycle_state USING btree (organization_id, feature_key) WHERE (notified_seq < transition_seq);

CREATE INDEX idx_feature_lifecycle_transition_pending ON public.feature_lifecycle_transition USING btree (feature_key, id) WHERE ((status)::text = 'PENDING'::text);

CREATE INDEX idx_gff_enabled ON public.global_feature_flags USING btree (enabled);

CREATE INDEX idx_gff_scope ON public.global_feature_flags USING btree (scope);

CREATE INDEX idx_incidents_alert_id ON public.incidents USING btree (alert_id);

CREATE INDEX idx_incidents_org_alert_id_created_at ON public.incidents USING btree (org_id, alert_id, created_at DESC);

CREATE INDEX idx_incidents_org_created_at ON public.incidents USING btree (org_id, created_at DESC);

CREATE INDEX idx_integrations_org_id ON public.integrations USING btree (org_id);

CREATE INDEX idx_integrations_org_provider_active_lookup ON public.integrations USING btree (org_id, provider) WHERE (deleted_at IS NULL);

CREATE INDEX idx_integrations_org_status ON public.integrations USING btree (org_id, status);

CREATE INDEX idx_iot_ca_health_org_status ON public.iot_ca_health_status USING btree (organization_id, health_status, checked_at DESC);

CREATE INDEX idx_iot_cert_enrollment_asserted_device ON public.iot_certificate_enrollment USING btree (device_source_id, asserted_source_device_id) WHERE (asserted_source_device_id IS NOT NULL);

CREATE INDEX idx_iot_cert_enrollment_device ON public.iot_certificate_enrollment USING btree (device_id, requested_at DESC) WHERE (device_id IS NOT NULL);

CREATE INDEX idx_iot_cert_enrollment_org_status ON public.iot_certificate_enrollment USING btree (organization_id, status, requested_at DESC);

CREATE INDEX idx_iot_cert_enrollment_pending_device ON public.iot_certificate_enrollment USING btree (device_source_id, asserted_source_device_id) WHERE ((device_match_status)::text = ANY ((ARRAY['DEVICE_NOT_SYNCED'::character varying, 'AMBIGUOUS'::character varying])::text[]));

CREATE INDEX idx_iot_cert_enrollment_pending_profile ON public.iot_certificate_enrollment USING btree (device_source_id, id) WHERE ((profile_resolution_status)::text = ANY ((ARRAY['PENDING_SYNC'::character varying, 'NOT_FOUND'::character varying, 'AMBIGUOUS'::character varying])::text[]));

CREATE INDEX idx_iot_certificate_profile_org ON public.iot_certificate_profile USING btree (organization_id, lifecycle_status, updated_at DESC);

CREATE INDEX idx_iot_certificate_profile_pending ON public.iot_certificate_profile USING btree (updated_at, id) WHERE ((provider_sync_status)::text = 'PENDING'::text);

CREATE INDEX idx_iot_certificate_profile_reconciliation ON public.iot_certificate_profile USING btree (device_source_id, last_provider_sync_xref) WHERE (((lifecycle_status)::text <> 'ARCHIVED'::text) AND (provider_profile_id IS NOT NULL));

CREATE INDEX idx_iot_certificate_profile_source ON public.iot_certificate_profile USING btree (device_source_id, control_mode, updated_at DESC);

CREATE INDEX idx_iot_certificate_profile_sync ON public.iot_certificate_profile USING btree (device_source_id, provider_sync_status, updated_at DESC);

CREATE INDEX idx_iot_certificate_revocation_due ON public.iot_certificate_revocation USING btree (next_attempt_at, id) WHERE ((status)::text = ANY ((ARRAY['PENDING'::character varying, 'DISPATCHED'::character varying])::text[]));

CREATE INDEX idx_iot_certificate_revocation_intune_batch ON public.iot_certificate_revocation USING btree (device_source_id, intune_transaction_id, status, id) WHERE (intune_transaction_id IS NOT NULL);

CREATE INDEX idx_iot_device_certificate_device_expiry ON public.iot_device_certificate USING btree (device_id, valid_to DESC) WHERE (device_id IS NOT NULL);

CREATE INDEX idx_iot_device_certificate_org_status_expiry ON public.iot_device_certificate USING btree (organization_id, status, valid_to);

CREATE INDEX idx_iot_device_certificate_renewal ON public.iot_device_certificate USING btree (organization_id, device_id, profile_id, issued_at DESC) WHERE (((status)::text = 'ISSUED'::text) AND (is_ca = false));

CREATE INDEX idx_iot_device_certificate_sans ON public.iot_device_certificate USING gin (subject_alt_names_json);

CREATE INDEX idx_iot_device_certificate_source_sha1 ON public.iot_device_certificate USING btree (device_source_id, fingerprint_sha1);

CREATE INDEX idx_iot_device_event_device ON public.iot_device_event USING btree (device_id, occurred_at DESC) WHERE (device_id IS NOT NULL);

CREATE INDEX idx_iot_device_event_enrollment ON public.iot_device_event USING btree (certificate_enrollment_id, occurred_at);

CREATE INDEX idx_iot_device_event_org_type ON public.iot_device_event USING btree (organization_id, event_type, occurred_at DESC);

CREATE INDEX idx_iot_device_org_class ON public.iot_device USING btree (organization_id, device_class) WHERE (is_deleted = false);

CREATE INDEX idx_iot_device_org_ownership ON public.iot_device USING btree (organization_id, ownership) WHERE (is_deleted = false);

CREATE INDEX idx_iot_device_org_status ON public.iot_device USING btree (organization_id, status) WHERE (is_deleted = false);

CREATE INDEX idx_iot_device_serial ON public.iot_device USING btree (organization_id, serial_number) WHERE ((serial_number IS NOT NULL) AND (is_deleted = false));

CREATE INDEX idx_iot_device_source_entra_device_id ON public.iot_device USING btree (device_source_id, ((source_identifiers_json ->> 'entraDeviceId'::text))) WHERE ((is_deleted = false) AND ((source_identifiers_json ->> 'entraDeviceId'::text) IS NOT NULL));

CREATE INDEX idx_iot_device_source_org ON public.iot_device_source USING btree (organization_id, status, created_at DESC);

CREATE INDEX idx_iot_device_source_seen ON public.iot_device USING btree (device_source_id, last_seen_in_source_at) WHERE (is_deleted = false);

CREATE INDEX idx_iot_device_source_syncable ON public.iot_device_source USING btree (last_advertised_at, id) WHERE ((sync_enabled = true) AND ((status)::text = 'ACTIVE'::text));

CREATE INDEX idx_iot_intune_revocation_poll_due ON public.iot_intune_revocation_poll_state USING btree (next_attempt_at, id);

CREATE INDEX idx_iot_owner_org ON public.iot_device_owner USING btree (organization_id);

CREATE INDEX idx_iot_posture_compliance ON public.iot_device_endpoint_posture USING btree (compliance_state);

CREATE INDEX idx_iot_profile_configuration_issuer ON public.iot_certificate_profile_configuration USING btree (organization_id, issuer_xref) WHERE (issuer_xref IS NOT NULL);

CREATE INDEX idx_iot_profile_snapshot_observed ON public.iot_certificate_profile_provider_snapshot USING btree (organization_id, provider_observed_at DESC);

CREATE INDEX idx_iot_source_event_correlation ON public.iot_device_source_event USING btree (device_source_id, correlation_id, occurred_at) WHERE (correlation_id IS NOT NULL);

CREATE INDEX idx_iot_source_event_org_type ON public.iot_device_source_event USING btree (organization_id, event_type, occurred_at DESC);

CREATE INDEX idx_iot_source_event_profile_xref ON public.iot_device_source_event USING btree (device_source_id, ((detail_json ->> 'profileXref'::text)), occurred_at DESC) WHERE (detail_json ? 'profileXref'::text);

CREATE INDEX idx_iot_source_event_source ON public.iot_device_source_event USING btree (device_source_id, occurred_at DESC);

CREATE INDEX idx_iot_source_health_observed ON public.iot_device_source_health_status USING btree (health_status, observed_at DESC);

CREATE INDEX idx_iot_source_sync_status ON public.iot_device_source_sync_state USING btree (sync_status, requested_at);

CREATE INDEX idx_off_feature_key ON public.organization_feature_flags USING btree (feature_key);

CREATE INDEX idx_off_org_enabled ON public.organization_feature_flags USING btree (organization_id, enabled) WHERE (is_deleted = false);

CREATE INDEX idx_off_organization ON public.organization_feature_flags USING btree (organization_id);

CREATE INDEX idx_organizations_domain ON public.organizations USING btree (domain);

CREATE INDEX idx_renewal_schedule_eligible ON public.renewal_schedule USING btree (renewal_eligible_at) WHERE ((enabled = true) AND ((last_renewal_status)::text IS DISTINCT FROM 'IN_PROGRESS'::text));

CREATE INDEX idx_renewal_schedule_retry_due ON public.renewal_schedule USING btree (next_attempt_at) WHERE (((last_renewal_status)::text = 'FAILED'::text) AND enabled AND (NOT is_deleted));

CREATE INDEX idx_revoked_access_expires ON public.auth_revoked_access_tokens USING btree (expires_at);

CREATE INDEX idx_revoked_access_user ON public.auth_revoked_access_tokens USING btree (user_id);

CREATE INDEX idx_role_permissions_role ON public.role_permissions USING btree (role_id);

CREATE INDEX idx_udc_domain ON public.user_domain_certificate USING btree (domain);

CREATE INDEX idx_udc_organization ON public.user_domain_certificate USING btree (organization_id);

CREATE INDEX idx_user_permissions_permission ON public.user_permissions USING btree (permission_id);

CREATE INDEX idx_user_permissions_user ON public.user_permissions USING btree (user_id);

CREATE INDEX idx_user_roles_role ON public.user_roles USING btree (role_id);

CREATE INDEX idx_user_roles_user ON public.user_roles USING btree (user_id);

CREATE INDEX idx_users_email ON public.users USING btree (email);

CREATE INDEX idx_users_email_authmethod ON public.users USING btree (email, auth_method) WHERE (is_deleted = false);

CREATE INDEX idx_users_idp_user_id ON public.users USING btree (idp_user_id);

CREATE INDEX idx_users_organization ON public.users USING btree (organization_id);

CREATE INDEX ix_agent_info_organization ON public.agent_info USING btree (organization_id);

CREATE INDEX ix_agent_result_receipts_org_request ON public.agent_result_receipts USING btree (organization_id, request_id);

CREATE INDEX ix_agent_result_receipts_token ON public.agent_result_receipts USING btree (agent_token_id, applied_at);

CREATE INDEX ix_agent_tokens_organization ON public.agent_tokens USING btree (organization_id);

CREATE INDEX ix_cert_deployment_config_lookup ON public.cert_deployment_config USING btree (organization_id, user_domain_cert_id, deployment_credential_id) WHERE (is_deleted = false);

CREATE INDEX ix_message_queue_channel_org_waiting ON public.message_queue USING btree (channel, ((properties ->> 'AuthenticatedOrganizationId'::text))) WHERE ((status)::text <> 'DEAD'::text);

CREATE INDEX ix_message_queue_leased ON public.message_queue USING btree (locked_until) WHERE ((status)::text = 'LEASED'::text);

CREATE INDEX ix_message_queue_ready ON public.message_queue USING btree (channel, priority DESC, available_at, id) WHERE ((status)::text = 'READY'::text);

CREATE INDEX ix_notification_records_correlation_id ON public.notification_records USING btree (correlation_id) WHERE (correlation_id IS NOT NULL);

CREATE INDEX ix_notification_records_organization_id_created_at ON public.notification_records USING btree (organization_id, created_at DESC);

CREATE INDEX ix_notification_records_status_created_at ON public.notification_records USING btree (status, created_at DESC);

CREATE INDEX ix_notification_records_user_id_created_at ON public.notification_records USING btree (user_id, created_at DESC);

CREATE UNIQUE INDEX spring_session_ix1 ON public.spring_session USING btree (session_id);

CREATE INDEX spring_session_ix2 ON public.spring_session USING btree (expiry_time);

CREATE INDEX spring_session_ix3 ON public.spring_session USING btree (principal_name);

CREATE UNIQUE INDEX uk_cirs_cert_workflow ON public.cert_issuance_retry_state USING btree (certificate_xref, workflow_type) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_iot_certificate_revocation_idempotency ON public.iot_certificate_revocation USING btree (organization_id, idempotency_key) WHERE (idempotency_key IS NOT NULL);

CREATE UNIQUE INDEX uk_iot_certificate_revocation_intune_request ON public.iot_certificate_revocation USING btree (device_source_id, request_context_hash) WHERE (request_context_hash IS NOT NULL);

CREATE UNIQUE INDEX uk_iot_device_event_dedupe ON public.iot_device_event USING btree (organization_id, dedupe_key) WHERE (dedupe_key IS NOT NULL);

CREATE UNIQUE INDEX uk_iot_profile_provider_id ON public.iot_certificate_profile USING btree (device_source_id, provider_profile_type, provider_profile_id) WHERE (provider_profile_id IS NOT NULL);

CREATE UNIQUE INDEX uk_iot_profile_provider_marker ON public.iot_certificate_profile USING btree (device_source_id, provider_correlation_marker) WHERE (provider_correlation_marker IS NOT NULL);

CREATE UNIQUE INDEX uk_off_org_feature_active ON public.organization_feature_flags USING btree (organization_id, feature_key) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_organizations_domain ON public.organizations USING btree (domain) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_organizations_name ON public.organizations USING btree (name) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_organizations_slug ON public.organizations USING btree (slug) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_role_permissions ON public.role_permissions USING btree (role_id, permission_id) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_roles_name_organization ON public.roles USING btree (name, organization_id) WHERE ((organization_id IS NOT NULL) AND (is_deleted = false));

CREATE UNIQUE INDEX uk_roles_system_name ON public.roles USING btree (name) WHERE ((organization_id IS NULL) AND (is_deleted = false));

CREATE UNIQUE INDEX uk_user_permissions ON public.user_permissions USING btree (user_id, permission_id) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_user_roles ON public.user_roles USING btree (user_id, role_id) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_users_email_global ON public.users USING btree (lower((email)::text)) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uk_users_username ON public.users USING btree (username) WHERE ((username IS NOT NULL) AND (is_deleted = false));

CREATE UNIQUE INDEX uq_cert_deployment_config_active ON public.cert_deployment_config USING btree (user_domain_cert_id, deployment_credential_id) WHERE (is_deleted = false);

CREATE UNIQUE INDEX uq_integrations_org_provider_active ON public.integrations USING btree (org_id, provider) WHERE (deleted_at IS NULL);

CREATE UNIQUE INDEX uq_udc_organization_domain ON public.user_domain_certificate USING btree (organization_id, domain) WHERE (is_deleted = false);

CREATE UNIQUE INDEX ux_agent_ca_status_agent ON public.agent_ca_status USING btree (organization_id, COALESCE(agent_token_id, (0)::bigint));

CREATE UNIQUE INDEX ux_certificates_single_active_per_udc ON public.certificates USING btree (user_domain_cert_id) WHERE (((status)::text = 'ACTIVE'::text) AND (deleted_at IS NULL));

CREATE UNIQUE INDEX ux_message_queue_channel_message_id ON public.message_queue USING btree (channel, message_id) WHERE (message_id IS NOT NULL);

CREATE UNIQUE INDEX ux_notification_records_request_id ON public.notification_records USING btree (request_id) WHERE (request_id IS NOT NULL);

ALTER INDEX public.audit_events_actor_idx ATTACH PARTITION public.audit_events_default_actor_user_id_idx;

ALTER INDEX public.audit_events_correlation_idx ATTACH PARTITION public.audit_events_default_correlation_id_idx;

ALTER INDEX public.audit_events_occurred_idx ATTACH PARTITION public.audit_events_default_occurred_at_id_idx;

ALTER INDEX public.audit_events_customer_actor_idx ATTACH PARTITION public.audit_events_default_organization_id_actor_user_id_occurred_idx;

ALTER INDEX public.audit_events_customer_category_idx ATTACH PARTITION public.audit_events_default_organization_id_category_occurred_at_i_idx;

ALTER INDEX public.audit_events_customer_idx ATTACH PARTITION public.audit_events_default_organization_id_occurred_at_id_idx;

ALTER INDEX public.audit_events_org_idx ATTACH PARTITION public.audit_events_default_organization_id_occurred_at_id_idx1;

ALTER INDEX public.audit_events_target_idx ATTACH PARTITION public.audit_events_default_organization_id_resource_type_resource_idx;

ALTER INDEX public.audit_events_pkey ATTACH PARTITION public.audit_events_default_pkey;

ALTER INDEX public.audit_events_request_idx ATTACH PARTITION public.audit_events_default_request_id_idx;

CREATE TRIGGER audit_events_append_only BEFORE DELETE OR UPDATE ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.audit_events_refuse_change();

CREATE TRIGGER audit_events_default_no_truncate BEFORE TRUNCATE ON public.audit_events_default FOR EACH STATEMENT EXECUTE FUNCTION public.audit_events_refuse_change();

CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON public.audit_events FOR EACH STATEMENT EXECUTE FUNCTION public.audit_events_refuse_change();

ALTER TABLE ONLY public.agent_ca_status
    ADD CONSTRAINT agent_ca_status_agent_token_id_fkey FOREIGN KEY (agent_token_id) REFERENCES public.agent_tokens(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_ca_status
    ADD CONSTRAINT agent_ca_status_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_info
    ADD CONSTRAINT agent_info_agent_token_id_fkey FOREIGN KEY (agent_token_id) REFERENCES public.agent_tokens(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_info
    ADD CONSTRAINT agent_info_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_result_receipts
    ADD CONSTRAINT agent_result_receipts_agent_token_id_fkey FOREIGN KEY (agent_token_id) REFERENCES public.agent_tokens(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.agent_result_receipts
    ADD CONSTRAINT agent_result_receipts_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_tokens
    ADD CONSTRAINT agent_tokens_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.discovered_cert_observation
    ADD CONSTRAINT discovered_cert_observation_discovered_cert_id_fkey FOREIGN KEY (discovered_cert_id) REFERENCES public.discovered_cert(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.discovered_cert_observation
    ADD CONSTRAINT discovered_cert_observation_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.discovered_cert
    ADD CONSTRAINT discovered_cert_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.discovery_config
    ADD CONSTRAINT discovery_config_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.discovery_scan
    ADD CONSTRAINT discovery_scan_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.feature_lifecycle_state
    ADD CONSTRAINT feature_lifecycle_state_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.feature_lifecycle_transition
    ADD CONSTRAINT feature_lifecycle_transition_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_health_status
    ADD CONSTRAINT fk_agent_health_status_organization FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.auth_refresh_tokens
    ADD CONSTRAINT fk_auth_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.auth_revoked_refresh_tokens
    ADD CONSTRAINT fk_auth_revoked_refresh_tokens_token FOREIGN KEY (token_id) REFERENCES public.auth_refresh_tokens(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.certificate_crypto_metadata
    ADD CONSTRAINT fk_cert_crypto_metadata_cert FOREIGN KEY (certificate_xref) REFERENCES public.certificates(certificate_xref) ON DELETE CASCADE;

ALTER TABLE ONLY public.certificate_events
    ADD CONSTRAINT fk_cert_events_cert FOREIGN KEY (certificate_xref) REFERENCES public.certificates(certificate_xref) ON DELETE RESTRICT;

ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT fk_cert_udc FOREIGN KEY (user_domain_cert_id) REFERENCES public.user_domain_certificate(id);

ALTER TABLE ONLY public.cert_issuance_retry_state
    ADD CONSTRAINT fk_cirs_certificate FOREIGN KEY (certificate_xref) REFERENCES public.certificates(certificate_xref) ON DELETE CASCADE;

ALTER TABLE ONLY public.credential_references
    ADD CONSTRAINT fk_credential_references_organization FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.domain_credential_config
    ADD CONSTRAINT fk_dcc_udc FOREIGN KEY (user_domain_cert_id) REFERENCES public.user_domain_certificate(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.global_feature_flags
    ADD CONSTRAINT fk_gff_updated_by FOREIGN KEY (updated_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT fk_iot_cert_enrollment_device FOREIGN KEY (device_id, organization_id, device_source_id) REFERENCES public.iot_device(id, organization_id, device_source_id);

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT fk_iot_cert_enrollment_profile FOREIGN KEY (profile_id, organization_id, device_source_id) REFERENCES public.iot_certificate_profile(id, organization_id, device_source_id);

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT fk_iot_cert_enrollment_source FOREIGN KEY (device_source_id, organization_id) REFERENCES public.iot_device_source(id, organization_id);

ALTER TABLE ONLY public.iot_certificate_profile
    ADD CONSTRAINT fk_iot_certificate_profile_source FOREIGN KEY (device_source_id, organization_id) REFERENCES public.iot_device_source(id, organization_id);

ALTER TABLE ONLY public.iot_certificate_revocation
    ADD CONSTRAINT fk_iot_certificate_revocation_certificate FOREIGN KEY (certificate_id, organization_id) REFERENCES public.iot_device_certificate(id, organization_id);

ALTER TABLE ONLY public.iot_certificate_revocation
    ADD CONSTRAINT fk_iot_certificate_revocation_source FOREIGN KEY (device_source_id, organization_id) REFERENCES public.iot_device_source(id, organization_id);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT fk_iot_device_certificate_device FOREIGN KEY (device_id, organization_id, device_source_id) REFERENCES public.iot_device(id, organization_id, device_source_id);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT fk_iot_device_certificate_enrollment FOREIGN KEY (enrollment_id, organization_id, device_source_id) REFERENCES public.iot_certificate_enrollment(id, organization_id, device_source_id);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT fk_iot_device_certificate_profile FOREIGN KEY (profile_id, organization_id, device_source_id) REFERENCES public.iot_certificate_profile(id, organization_id, device_source_id);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT fk_iot_device_certificate_source FOREIGN KEY (device_source_id, organization_id) REFERENCES public.iot_device_source(id, organization_id);

ALTER TABLE ONLY public.iot_device_event
    ADD CONSTRAINT fk_iot_device_event_device FOREIGN KEY (device_id, organization_id) REFERENCES public.iot_device(id, organization_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iot_device_event
    ADD CONSTRAINT fk_iot_device_event_enrollment FOREIGN KEY (certificate_enrollment_id, organization_id) REFERENCES public.iot_certificate_enrollment(id, organization_id);

ALTER TABLE ONLY public.iot_intune_revocation_poll_state
    ADD CONSTRAINT fk_iot_intune_revocation_poll_source FOREIGN KEY (device_source_id, organization_id) REFERENCES public.iot_device_source(id, organization_id);

ALTER TABLE ONLY public.iot_certificate_profile_configuration
    ADD CONSTRAINT fk_iot_profile_configuration FOREIGN KEY (profile_id, organization_id, device_source_id) REFERENCES public.iot_certificate_profile(id, organization_id, device_source_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iot_certificate_profile_provider_snapshot
    ADD CONSTRAINT fk_iot_profile_snapshot FOREIGN KEY (profile_id, organization_id, device_source_id) REFERENCES public.iot_certificate_profile(id, organization_id, device_source_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.organization_feature_flags
    ADD CONSTRAINT fk_off_organization FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.organization_feature_flags
    ADD CONSTRAINT fk_off_updated_by FOREIGN KEY (updated_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.org_type_feature_flags
    ADD CONSTRAINT fk_otff_updated_by FOREIGN KEY (updated_by_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.renewal_schedule
    ADD CONSTRAINT fk_renewal_schedule_cert FOREIGN KEY (certificate_xref) REFERENCES public.certificates(certificate_xref) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT fk_roles_organization FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.renewal_schedule
    ADD CONSTRAINT fk_rs_dcc FOREIGN KEY (domain_credential_config_id) REFERENCES public.domain_credential_config(id);

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT fk_user_permissions_granted_by FOREIGN KEY (granted_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT fk_user_permissions_permission FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_permissions
    ADD CONSTRAINT fk_user_permissions_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT fk_user_roles_assigned_by FOREIGN KEY (assigned_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.users
    ADD CONSTRAINT fk_users_organization FOREIGN KEY (organization_id) REFERENCES public.organizations(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.global_settings
    ADD CONSTRAINT global_settings_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.iot_ca_health_status
    ADD CONSTRAINT iot_ca_health_status_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_certificate_enrollment
    ADD CONSTRAINT iot_certificate_enrollment_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_certificate_profile
    ADD CONSTRAINT iot_certificate_profile_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_certificate_revocation
    ADD CONSTRAINT iot_certificate_revocation_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_device_certificate
    ADD CONSTRAINT iot_device_certificate_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_device_connected_thing
    ADD CONSTRAINT iot_device_connected_thing_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.iot_device(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iot_device
    ADD CONSTRAINT iot_device_device_source_id_fkey FOREIGN KEY (device_source_id) REFERENCES public.iot_device_source(id);

ALTER TABLE ONLY public.iot_device_endpoint_posture
    ADD CONSTRAINT iot_device_endpoint_posture_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.iot_device(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iot_device_event
    ADD CONSTRAINT iot_device_event_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_device
    ADD CONSTRAINT iot_device_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_device_owner
    ADD CONSTRAINT iot_device_owner_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.iot_device(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iot_device_owner
    ADD CONSTRAINT iot_device_owner_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_device_source_event
    ADD CONSTRAINT iot_device_source_event_device_source_id_fkey FOREIGN KEY (device_source_id) REFERENCES public.iot_device_source(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iot_device_source_event
    ADD CONSTRAINT iot_device_source_event_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_device_source_health_status
    ADD CONSTRAINT iot_device_source_health_status_device_source_id_fkey FOREIGN KEY (device_source_id) REFERENCES public.iot_device_source(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iot_device_source
    ADD CONSTRAINT iot_device_source_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.iot_device_source_sync_state
    ADD CONSTRAINT iot_device_source_sync_state_device_source_id_fkey FOREIGN KEY (device_source_id) REFERENCES public.iot_device_source(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.iot_intune_revocation_poll_state
    ADD CONSTRAINT iot_intune_revocation_poll_state_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);

ALTER TABLE ONLY public.spring_session_attributes
    ADD CONSTRAINT spring_session_attributes_fk FOREIGN KEY (session_primary_id) REFERENCES public.spring_session(primary_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.user_mfa
    ADD CONSTRAINT user_mfa_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

-- ── Seed data ───────────────────────────────────────────────────────────────────

INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (1, 'CERTIFICATE_ISSUANCE', 'Certificate Issuance', 'Automated certificate issuance via ACME, DigiCert, or GlobalSign', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (3, 'CERTIFICATE_DEPLOYMENT', 'Certificate Deployment', 'Deploy certificates to Kubernetes, AWS, Azure, GCP, Cloudflare, Akamai and F5', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (4, 'CERTIFICATE_REVOCATION', 'Certificate Revocation', 'Revoke issued certificates', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (5, 'CREDENTIALS_MANAGEMENT', 'Credentials Management', 'Create, update, and delete DNS and deployment credential references', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (7, 'ALERTS', 'Alerts', 'Certificate expiry and system alert records', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (9, 'AGENT_HEALTH_MONITORING', 'Agent Health Monitoring', 'Agent health dashboard and heartbeat cadence management', 'ORG', 'B2B', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (19, 'DIGICERT', 'DigiCert CA', 'Certificate issuance and renewal via DigiCert', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (20, 'GLOBALSIGN', 'GlobalSign CA', 'Certificate issuance and renewal via GlobalSign', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (21, 'LETS_ENCRYPT', 'Let''s Encrypt CA', 'Certificate issuance and renewal via Let''s Encrypt (ACME)', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (22, 'AUTO_RENEWAL', 'Automated Renewal', 'Scheduler-driven automatic certificate renewal job', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (23, 'EXPIRY_ALERTS', 'Expiry Alerts', 'Pre-expiry alert scheduler job', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (24, 'EXPIRY_MARKING', 'Cron: Mark Expired Certs', 'Nightly job that flips status=EXPIRED on certs whose valid_to has passed and disables their renewal schedules. Disable only as incident-response — UI will continue to show expired certs as ACTIVE until the job runs.', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (25, 'ISSUANCE_RETRY', 'Issuance Retry', 'Automatic retry of failed certificate issuance workflows', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (30, 'SOFT_DELETE_PURGE', 'Cron: Hard-Delete Soft-Deleted Records', 'Nightly job that hard-deletes records that have been soft-deleted for longer than each organization''s retention period. COMPLIANCE-SENSITIVE: prolonged disable will put retention SLAs out of compliance.', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (31, 'AUDIT_LOGS', 'Audit Logs', 'Audit log access (compliance-sensitive; super admin control only)', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (10, 'CERTIFICATE_MANUAL_ISSUANCE', 'Manual Certificate Issuance', 'Manual DNS-01 certificate issuance with TXT record validation', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:37.027321+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (29, 'EXPIRED_CERT_SOFT_DELETE', 'Cron: Soft-Delete Expired/Revoked Certs', 'Daily job that soft-deletes certs that have been in EXPIRED or REVOKED state for more than 24 hours, cascading to renewal_schedule and queueing CERT_SECRET_DELETE_COMMAND to the agent. Disable to halt all cert soft-deletes platform-wide.', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:36.891164+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (2, 'CERTIFICATE_RENEWAL', 'Certificate Renewal', 'Renewal of every certificate in the organization, automatic and on request', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:43.282333+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (39, 'QUEUE_DEPTH_ALERTS', 'Cron: Queue Depth / DLQ Alerts', 'Scheduled job that reads the active and dead-lettered message counts of the configured message queue channels and emails the super admin when a threshold is breached (and again when it recovers). Operational health signal only; does not affect organization notifications. Enabled by default; does nothing until the watch-list (certping.alerts.queue-depth.entities) is configured. A super admin can turn it off as a runtime kill switch.', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:37.582611+00', '2026-11-06 20:25:37.582611+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (44, 'IOT_DEVICE_MANAGEMENT', 'IoT Device Management', 'Device identity registry sourced from endpoint-management and IoT platforms.', 'ORG', 'B2B', true, NULL, '2026-11-06 20:25:39.304486+00', '2026-11-06 20:25:39.304486+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (45, 'IOT_PROVIDER_INTUNE', 'Microsoft Intune Device Source', 'Microsoft Intune device discovery and source health.', 'ORG', 'B2B', true, NULL, '2026-11-06 20:25:39.304486+00', '2026-11-06 20:25:39.304486+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (46, 'IOT_CERTIFICATE_PROFILE_MANAGEMENT', 'IoT Certificate Profile Management', 'Discover and manage certificate delivery profiles on connected device platforms.', 'ORG', 'B2B', true, NULL, '2026-11-06 20:25:39.304486+00', '2026-11-06 20:25:39.304486+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (47, 'CA_EJBCA', 'EJBCA Certificate Authority', 'EJBCA SCEP certificate authority connector for IoT device enrollment.', 'ORG', 'B2B', true, NULL, '2026-11-06 20:25:39.304486+00', '2026-11-06 20:25:39.304486+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (48, 'CA_SMALLSTEP', 'Smallstep Certificate Authority', 'Smallstep (step-ca) SCEP certificate authority connector for IoT device enrollment.', 'ORG', 'B2B', true, NULL, '2026-11-06 20:25:39.304486+00', '2026-11-06 20:25:39.304486+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (52, 'PQC_READINESS', 'PQC Readiness and CBOM', 'Post-quantum readiness report and CycloneDX CBOM download for the organization''s certificates.', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:40.390481+00', '2026-11-06 20:25:40.390481+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (54, 'DISCOVERY', 'Certificate discovery', 'Scan cloud targets (Key Vault, ACM, Kubernetes and others) with a deployment credential and list the certificates found there. When off, scans cannot be started and results arriving for running scans are dropped and the scan cancelled.', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:41.377684+00', '2026-11-06 20:25:41.377684+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (55, 'FEATURE_LIFECYCLE_RECONCILE', 'Cron: Feature lifecycle baseline and backstop sweep', 'Periodic sweep that pauses (silently, audited as system:baseline) the records of organizations whose feature is already off, and resumes platform-paused records whose feature is back on. Super-admin switch-offs made after deploy are applied immediately whatever this says. Seeded DISABLED; check GET /api/v1/admin/feature-lifecycle/baseline-preview, then enable.', 'PLATFORM', 'PLATFORM', false, NULL, '2026-11-06 20:25:41.57872+00', '2026-11-06 20:25:41.57872+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (57, 'AUDIT_RETENTION_PURGE', 'Cron: Drop Expired Audit Months', 'Job that drops audit-event months older than the audit retention setting. COMPLIANCE-SENSITIVE: off keeps audit data, including IP addresses, past the retention period.', 'PLATFORM', 'PLATFORM', true, NULL, '2026-11-06 20:25:41.872423+00', '2026-11-06 20:25:41.872423+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (56, 'CERTIFICATE_DOWNLOAD', 'Certificate download', 'Download certificates stored by the platform, from any CA, as PEM or PKCS#12, including the private key.', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:41.752976+00', '2026-11-06 20:25:41.752976+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (64, 'DNS_CREDENTIALS', 'DNS Credentials', 'Add, edit and remove DNS provider credentials for DNS-01 validation', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:43.025767+00', '2026-11-06 20:25:43.025767+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (65, 'INTEGRATIONS', 'Integrations', 'Slack, Teams, webhook, PagerDuty and ServiceNow integrations and their delivery', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:43.025767+00', '2026-11-06 20:25:43.025767+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (66, 'FEATURE_FLAGS_PAGE', 'Feature flags page', 'Organization admins can view and change their workspace feature flags', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:43.025767+00', '2026-11-06 20:25:43.025767+00');
INSERT INTO public.global_feature_flags (id, feature_key, display_name, description, scope, category, enabled, updated_by_user_id, created_at, updated_at) VALUES (67, 'NOTIFICATION_PREFERENCES', 'Notification settings', 'Organization admins can turn off informational notifications for their organization', 'ORG', 'PLATFORM', true, NULL, '2026-11-06 20:25:43.14607+00', '2026-11-06 20:25:43.14607+00');

INSERT INTO public.global_settings (key, value, description, updated_at, updated_by) VALUES ('soft_delete_retention_days', '30', 'Default days before soft-deleted records are hard-purged. Overridable per organization.', '2026-11-06 20:25:36.891164+00', NULL);
INSERT INTO public.global_settings (key, value, description, updated_at, updated_by) VALUES ('audit_retention_months', '12', 'Months audit events are kept before their monthly partition is dropped (6-36). Rows are kept up to one extra month.', '2026-11-06 20:25:41.872423+00', NULL);

INSERT INTO public.org_type_feature_flags (id, org_type, feature_key, enabled, updated_by_user_id, created_at, updated_at) VALUES (4, 'B2B', 'NOTIFICATION_PREFERENCES', false, NULL, '2026-11-06 20:25:43.14607+00', '2026-11-06 20:25:43.14607+00');

INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (1, 'deployments:view', 'deployments', 'view', 'View deployments', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (2, 'users:manage', 'users', 'manage', 'Manage users', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (3, 'audit:view', 'audit', 'view', 'View audit logs', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (4, 'notifications:view', 'notifications', 'view', 'View notifications', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (11, 'organization:view', 'organization', 'view', 'View organization details', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (12, 'organization:manage', 'organization', 'manage', 'Create and update organization settings', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (13, 'users:view', 'users', 'view', 'View users', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (14, 'users:create', 'users', 'create', 'Create users', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (15, 'users:delete', 'users', 'delete', 'Delete users', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (16, 'roles:view', 'roles', 'view', 'View roles and their permissions', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (17, 'roles:create', 'roles', 'create', 'Create custom roles', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (18, 'roles:delete', 'roles', 'delete', 'Delete custom roles', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (19, 'roles:assign', 'roles', 'assign', 'Assign roles to users', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (20, 'permissions:view', 'permissions', 'view', 'View all permissions', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (21, 'permissions:assign', 'permissions', 'assign', 'Assign permissions to roles', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (22, 'certificate:issue', 'certificate', 'issue', 'Issue certificates', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (23, 'certificate:renew', 'certificate', 'renew', 'Renew certificates', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (24, 'certificate:deploy', 'certificate', 'deploy', 'Deploy certificates', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (25, 'certificate:read', 'certificate', 'read', 'Read certificate status and metadata', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (26, 'certificate:delete', 'certificate', 'delete', 'Delete certificates', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (27, 'certificate:revoke', 'certificate', 'revoke', 'Revoke certificates', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (28, 'alerts:view', 'alerts', 'view', 'View alerts', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (29, 'alerts:update', 'alerts', 'update', 'Update alert state', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (30, 'credential:create', 'credential', 'create', 'Create credential references', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (31, 'credential:read', 'credential', 'read', 'Read credential references', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (32, 'credential:delete', 'credential', 'delete', 'Delete credential references', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (33, 'credential:rotate', 'credential', 'rotate', 'Rotate credential references', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (34, 'agent-deep-health:read', 'agent-deep-health', 'read', 'List and view agent deep health checks and metrics', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (35, 'feature_flags:view', 'feature_flags', 'view', 'View feature flag states', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (36, 'feature_flags:manage', 'feature_flags', 'manage', 'Manage org-level feature flag overrides', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (37, 'feature_flags:administer', 'feature_flags', 'administer', 'Manage global feature flags and all org overrides', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (38, 'integrations:view', 'integrations', 'view', 'View organization integrations (Slack/Teams/PagerDuty/ServiceNow)', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (39, 'integrations:manage', 'integrations', 'manage', 'Create, update, and delete organization integrations', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (40, 'incidents:view', 'incidents', 'view', 'View organization incident history', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (41, 'incidents:create', 'incidents', 'create', 'Trigger PagerDuty and ServiceNow incidents', false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (64, 'iot_device:view', 'iot_device', 'view', 'View device inventory and history', false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (65, 'iot_device:manage', 'iot_device', 'manage', 'Decommission devices', false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (66, 'iot_source:view', 'iot_source', 'view', 'View device sources and their health', false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (67, 'iot_source:manage', 'iot_source', 'manage', 'Start or stop device-source synchronization', false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (68, 'iot_certificate_profile:view', 'iot_certificate_profile', 'view', 'View certificate delivery profiles and provider state', false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (69, 'iot_certificate_profile:manage', 'iot_certificate_profile', 'manage', 'Create and update certificate delivery profiles', false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (70, 'iot_certificate_profile:sync', 'iot_certificate_profile', 'sync', 'Synchronize certificate profiles from a connected device source', false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.permissions (id, name, resource, action, description, is_deleted, created_at) VALUES (71, 'iot_ca_health:view', 'iot_ca_health', 'view', 'View private CA connector health', false, '2026-11-06 20:25:39.304486+00');

INSERT INTO public.roles (id, name, description, organization_id, is_system_role, is_deleted, created_at, updated_at) VALUES (1, 'SUPER_ADMIN', 'Platform Super Admin: platform configuration, organizations, platform-wide audit', NULL, true, false, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:44.086636+00');
INSERT INTO public.roles (id, name, description, organization_id, is_system_role, is_deleted, created_at, updated_at) VALUES (2, 'ORGANIZATION_ADMIN', 'Organization Admin: settings, members, discovery, rotation, deployment and credential configuration, audit', NULL, true, false, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:44.086636+00');
INSERT INTO public.roles (id, name, description, organization_id, is_system_role, is_deleted, created_at, updated_at) VALUES (7, 'VIEWER', 'Viewer: read-only access to certificates, discovery, PQC, rotation, deployments and audit', NULL, true, false, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:44.086636+00');
INSERT INTO public.roles (id, name, description, organization_id, is_system_role, is_deleted, created_at, updated_at) VALUES (14, 'SECURITY_ANALYST', 'Security Analyst: inventory, discovery, PQC readiness, rotation and deployment status; runs approved operations', NULL, true, false, '2026-11-06 20:25:36.891164+00', '2026-11-06 20:25:44.086636+00');

INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (1, 1, 3, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (2, 1, 14, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (3, 1, 16, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (4, 1, 11, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (5, 1, 12, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (6, 1, 34, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (7, 1, 2, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (8, 1, 20, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (9, 1, 19, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (10, 1, 15, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (11, 1, 13, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (12, 2, 38, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (14, 2, 32, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (15, 2, 24, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (18, 2, 19, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (20, 2, 21, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (21, 2, 13, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (22, 2, 15, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (25, 2, 40, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (27, 2, 2, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (28, 2, 18, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (29, 2, 12, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (31, 2, 34, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (32, 2, 33, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (33, 2, 17, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (34, 2, 31, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (36, 2, 39, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (37, 2, 11, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (38, 2, 27, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (39, 2, 26, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (40, 2, 25, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (41, 2, 20, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (44, 2, 14, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (47, 2, 3, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (49, 2, 1, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (51, 2, 22, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (52, 2, 4, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (55, 2, 23, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (57, 2, 16, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (59, 2, 41, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (60, 2, 29, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (65, 2, 30, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (66, 2, 28, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (90, 7, 3, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (91, 7, 1, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (92, 7, 4, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (93, 7, 16, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (94, 7, 28, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (96, 7, 13, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (97, 7, 31, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (98, 7, 11, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (99, 7, 25, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (100, 7, 20, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (104, 1, 35, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (105, 1, 36, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (106, 1, 37, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (153, 14, 28, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (172, 7, 38, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (174, 7, 40, false, '2026-11-06 20:25:36.891164+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (177, 1, 21, false, '2026-11-06 20:25:37.150503+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (191, 2, 68, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (192, 1, 67, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (193, 1, 69, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (194, 2, 65, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (195, 2, 64, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (196, 2, 66, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (197, 1, 70, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (198, 1, 66, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (199, 1, 64, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (200, 2, 70, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (201, 1, 65, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (202, 2, 69, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (203, 1, 68, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (204, 2, 67, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (205, 2, 71, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (206, 1, 71, false, '2026-11-06 20:25:39.304486+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (227, 7, 64, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (228, 7, 66, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (229, 7, 71, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (230, 7, 68, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (231, 7, 34, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (232, 14, 25, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (233, 14, 1, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (234, 14, 31, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (235, 14, 4, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (236, 14, 3, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (237, 14, 40, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (238, 14, 38, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (240, 14, 64, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (241, 14, 66, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (242, 14, 71, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (243, 14, 68, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (244, 14, 11, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (245, 14, 13, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (246, 14, 16, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (247, 14, 20, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (248, 14, 34, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (249, 14, 23, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (250, 14, 24, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (251, 14, 29, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (252, 14, 41, false, '2026-11-06 20:25:44.086636+00');
INSERT INTO public.role_permissions (id, role_id, permission_id, is_deleted, created_at) VALUES (254, 14, 70, false, '2026-11-06 20:25:44.086636+00');

SELECT pg_catalog.setval('public.global_feature_flags_id_seq', 68, true);

SELECT pg_catalog.setval('public.org_type_feature_flags_id_seq', 5, true);

SELECT pg_catalog.setval('public.permissions_id_seq', 76, true);

SELECT pg_catalog.setval('public.role_permissions_id_seq', 254, true);

SELECT pg_catalog.setval('public.roles_id_seq', 15, true);

-- Monthly audit partitions from twelve months back to three ahead. The partition job keeps the
-- window moving; a row whose month has no partition lands in audit_events_default.
DO $$
DECLARE
    this_month date := date_trunc('month', now() AT TIME ZONE 'UTC')::date;
    m int;
BEGIN
    FOR m IN -12..3 LOOP
        PERFORM audit_events_create_partition(
            ((this_month + make_interval(months => m))::timestamp) AT TIME ZONE 'UTC');
    END LOOP;
END
$$;
