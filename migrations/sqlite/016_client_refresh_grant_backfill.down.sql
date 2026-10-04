-- No-op: the backfilled clients cannot be told apart from clients registered
-- with both grants, and older releases ignore refresh_token in grant_types.
SELECT 1;
