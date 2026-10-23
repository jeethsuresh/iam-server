-- Trusted operator task: grant global admin access to one existing active user.
-- Run with psql -X -v ON_ERROR_STOP=1 -v username=TARGET_USERNAME.
-- No password or bootstrap configuration is modified. Safe to repeat.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15s';

-- \gset fails (and the transaction rolls back) if the account is absent/inactive.
SELECT id AS principal_id
FROM principals
WHERE username = :'username' AND type = 'user' AND active = true
FOR UPDATE
\gset

INSERT INTO roles (id, name, description, inserted_at, updated_at)
VALUES (gen_random_uuid(), 'admin', 'Global IAM administration', now(), now())
ON CONFLICT (name) DO NOTHING;

INSERT INTO grants (id, principal_id, role_id, resource_id, inserted_at, updated_at)
SELECT gen_random_uuid(), :'principal_id'::uuid, id, NULL, now(), now()
FROM roles WHERE name = 'admin'
ON CONFLICT (principal_id, role_id) WHERE resource_id IS NULL DO NOTHING;

SELECT p.username, p.active, r.name AS global_role
FROM principals p
JOIN grants g ON g.principal_id = p.id AND g.resource_id IS NULL
JOIN roles r ON r.id = g.role_id
WHERE p.id = :'principal_id'::uuid AND r.name = 'admin';
COMMIT;
