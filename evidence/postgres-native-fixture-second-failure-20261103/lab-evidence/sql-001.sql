-- Synthetic future integration schema only; not UDP or another owner's schema.
-- No runner executes this file in the current pure-library qualification.
CREATE SCHEMA ouf_recovery_fixture;
CREATE TABLE ouf_recovery_fixture.generation (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    generation text NOT NULL,
    accepting_writes boolean NOT NULL,
    active_writers integer NOT NULL CHECK (active_writers >= 0),
    pending_acknowledgements integer NOT NULL CHECK (pending_acknowledgements >= 0)
);
CREATE TABLE ouf_recovery_fixture.objects (
    bucket text NOT NULL CHECK (bucket = 'ouf-recovery-fixture'),
    object_key text NOT NULL CHECK (octet_length(object_key) BETWEEN 1 AND 1024),
    generation text NOT NULL,
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    content_bytes bigint NOT NULL CHECK (content_bytes BETWEEN 0 AND 16777216),
    ack_state text NOT NULL CHECK (ack_state IN ('PENDING', 'ACKED')),
    PRIMARY KEY (bucket, object_key)
);
-- The later adapter must own atomic admission/fencing and export a complete
-- read-only snapshot. These tables alone do not implement that protocol.
