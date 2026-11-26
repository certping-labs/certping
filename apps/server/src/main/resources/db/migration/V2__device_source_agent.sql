-- The agent token that last advertised each device source. Commands for the source go to that agent,
-- because only it holds the source's credentials (and, for SCEP, its CA).
ALTER TABLE public.iot_device_source ADD COLUMN advertising_agent_token_id bigint;
