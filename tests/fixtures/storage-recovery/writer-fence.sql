-- Disposable PostgreSQL fixture, not an OUF runtime schema or grant.
CREATE SCHEMA ouf_fence_lab;
REVOKE ALL ON SCHEMA ouf_fence_lab FROM PUBLIC;
CREATE TABLE ouf_fence_lab.control (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 epoch bigint NOT NULL CHECK(epoch > 0),
 version bigint NOT NULL CHECK(version >= 0),
 phase text NOT NULL CHECK(phase IN ('ACTIVE','DRAINING','FROZEN'))
);
INSERT INTO ouf_fence_lab.control VALUES(true,1,0,'ACTIVE');
CREATE TABLE ouf_fence_lab.intents (
 operation text PRIMARY KEY CHECK(operation ~ '^lab-[a-z0-9-]{1,48}$'),
 epoch bigint NOT NULL,
 body_hash text NOT NULL CHECK(body_hash ~ '^[0-9a-f]{64}$'),
 body_bytes bigint NOT NULL CHECK(body_bytes BETWEEN 0 AND 4096),
 state text NOT NULL CHECK(state IN ('PENDING','ACKED','RECONCILED'))
);
CREATE TABLE ouf_fence_lab.events (
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 kind text NOT NULL,
 operation text,
 epoch bigint NOT NULL,
 version bigint NOT NULL
);
CREATE FUNCTION ouf_fence_lab.reserve(op text, expected_epoch bigint, digest text, size bigint)
RETURNS text STRICT LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ouf_fence_lab AS $$
DECLARE c ouf_fence_lab.control; previous ouf_fence_lab.intents;
BEGIN
 SELECT * INTO c FROM ouf_fence_lab.control WHERE singleton FOR UPDATE;
 SELECT * INTO previous FROM ouf_fence_lab.intents WHERE operation=op;
 IF FOUND THEN
  IF previous.epoch <> expected_epoch OR previous.body_hash <> digest OR previous.body_bytes <> size THEN
   RETURN 'CONFLICT';
  END IF;
  -- A repeated intent never grants a second external write, even after restart.
  RETURN 'EXISTING_' || previous.state;
 END IF;
 IF c.phase <> 'ACTIVE' OR c.epoch <> expected_epoch THEN RETURN 'FENCED'; END IF;
 INSERT INTO ouf_fence_lab.intents VALUES(op,expected_epoch,digest,size,'PENDING');
 INSERT INTO ouf_fence_lab.events(kind,operation,epoch,version) VALUES('RESERVED',op,c.epoch,c.version);
 RETURN 'RESERVED';
END $$;
CREATE FUNCTION ouf_fence_lab.finish(op text, expected_epoch bigint, digest text, size bigint)
RETURNS text STRICT LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, ouf_fence_lab AS $$
DECLARE c ouf_fence_lab.control; previous ouf_fence_lab.intents;
BEGIN
 SELECT * INTO c FROM ouf_fence_lab.control WHERE singleton FOR UPDATE;
 IF c.phase <> 'ACTIVE' OR c.epoch <> expected_epoch THEN RETURN 'FENCED'; END IF;
 SELECT * INTO previous FROM ouf_fence_lab.intents WHERE operation=op FOR UPDATE;
 IF NOT FOUND OR previous.epoch <> expected_epoch OR previous.body_hash <> digest OR previous.body_bytes <> size THEN RETURN 'CONFLICT'; END IF;
 IF previous.state <> 'PENDING' THEN RETURN 'EXISTING_' || previous.state; END IF;
 UPDATE ouf_fence_lab.intents SET state='ACKED' WHERE operation=op;
 INSERT INTO ouf_fence_lab.events(kind,operation,epoch,version) VALUES('ACKED',op,c.epoch,c.version);
 RETURN 'ACKED';
END $$;
-- Administrative functions are intentionally unavailable to the writer role.
CREATE FUNCTION ouf_fence_lab.begin_drain(expected_epoch bigint, expected_version bigint)
RETURNS text STRICT LANGUAGE plpgsql SET search_path = pg_catalog, ouf_fence_lab AS $$
DECLARE c ouf_fence_lab.control;
BEGIN
 SELECT * INTO c FROM ouf_fence_lab.control WHERE singleton FOR UPDATE;
 IF c.phase <> 'ACTIVE' OR c.epoch <> expected_epoch OR c.version <> expected_version THEN RETURN 'STALE'; END IF;
 UPDATE ouf_fence_lab.control SET phase='DRAINING',epoch=epoch+1,version=version+1 WHERE singleton;
 INSERT INTO ouf_fence_lab.events(kind,epoch,version) VALUES('DRAINING',c.epoch+1,c.version+1);
 RETURN 'DRAINING';
END $$;
CREATE FUNCTION ouf_fence_lab.reconcile(op text, expected_version bigint, digest text, size bigint)
RETURNS text STRICT LANGUAGE plpgsql SET search_path = pg_catalog, ouf_fence_lab AS $$
DECLARE c ouf_fence_lab.control; previous ouf_fence_lab.intents;
BEGIN
 SELECT * INTO c FROM ouf_fence_lab.control WHERE singleton FOR UPDATE;
 IF c.phase <> 'DRAINING' OR c.version <> expected_version THEN RETURN 'STALE'; END IF;
 SELECT * INTO previous FROM ouf_fence_lab.intents WHERE operation=op FOR UPDATE;
 IF NOT FOUND OR previous.body_hash <> digest OR previous.body_bytes <> size THEN RETURN 'CONFLICT'; END IF;
 IF previous.state <> 'PENDING' THEN RETURN 'EXISTING_' || previous.state; END IF;
 UPDATE ouf_fence_lab.intents SET state='RECONCILED' WHERE operation=op;
 INSERT INTO ouf_fence_lab.events(kind,operation,epoch,version) VALUES('RECONCILED',op,c.epoch,c.version);
 RETURN 'RECONCILED';
END $$;
CREATE FUNCTION ouf_fence_lab.finish_drain(expected_version bigint)
RETURNS text STRICT LANGUAGE plpgsql SET search_path = pg_catalog, ouf_fence_lab AS $$
DECLARE c ouf_fence_lab.control;
BEGIN
 SELECT * INTO c FROM ouf_fence_lab.control WHERE singleton FOR UPDATE;
 IF c.phase <> 'DRAINING' OR c.version <> expected_version THEN RETURN 'STALE'; END IF;
 IF EXISTS(SELECT 1 FROM ouf_fence_lab.intents WHERE state='PENDING') THEN RETURN 'RECONCILE_REQUIRED'; END IF;
 UPDATE ouf_fence_lab.control SET phase='FROZEN',version=version+1 WHERE singleton;
 INSERT INTO ouf_fence_lab.events(kind,epoch,version) VALUES('FROZEN',c.epoch,c.version+1);
 RETURN 'FROZEN';
END $$;
REVOKE ALL ON ALL TABLES IN SCHEMA ouf_fence_lab FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ouf_fence_lab FROM PUBLIC;
CREATE ROLE ouf_fence_writer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
REVOKE ALL ON DATABASE ouf_recovery_fixture FROM PUBLIC;
GRANT CONNECT ON DATABASE ouf_recovery_fixture TO ouf_fence_writer;
GRANT USAGE ON SCHEMA ouf_fence_lab TO ouf_fence_writer;
GRANT EXECUTE ON FUNCTION ouf_fence_lab.reserve(text,bigint,text,bigint), ouf_fence_lab.finish(text,bigint,text,bigint) TO ouf_fence_writer;
