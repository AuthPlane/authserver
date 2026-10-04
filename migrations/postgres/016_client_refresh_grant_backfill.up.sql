-- Refresh tokens are honoured only for clients whose grant_types include
-- refresh_token. Earlier releases issued them to every authorization_code
-- client and stored ["authorization_code"] when registration omitted
-- grant_types (DCR, CIMD, admin API, CLI default). Clients stored that way
-- keep refresh across the upgrade; a stored list cannot tell a default from
-- an explicit choice, so every exact ["authorization_code"] is widened.
-- To withdraw refresh from a client, PATCH its grant_types afterwards.
UPDATE clients
   SET grant_types = '["authorization_code","refresh_token"]'::jsonb
 WHERE grant_types = '["authorization_code"]'::jsonb;
