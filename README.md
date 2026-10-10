# supabase-rls-ab-test

A two-account check for Supabase Row Level Security. One Python file, no dependencies.

Scanners can tell you RLS is *enabled*. They can't tell you whether user B can read user A's rows, because they don't know which rows belong to whom. This script signs in as two real test users and tries.

## What it checks

| Check | Default | How |
|---|---|---|
| B reads A's rows | on | `GET /rest/v1/<table>` as B, then counts rows whose owner column is A's id |
| Signed-out visitor reads the table | on | Same request with only the public key. Reported as `OPEN` (fine for public tables) |
| B updates A's rows | `--write` | No-op `PATCH` that writes the owner column back to A's id. Counts returned rows, because a blocked update usually returns 200 with zero rows |
| B lists A's storage files | `--bucket NAME` | `POST /storage/v1/object/list/NAME` with prefix = A's user id |

Not covered: DELETE, INSERT with someone else's id, RPC functions, Edge Functions, and server routes that use a secret key. Test those by hand ([checklist](https://madlouse.github.io/toolstack-lab/tools/supabase-audit-checklist.html#ab-test)).

## Run it

1. In **staging** (or a project you own), create two test users, A and B, with email + password sign-in.
2. As A, create at least one row in each table you want to test (and one file under `A's-user-id/` in any bucket).
3. Run:

```bash
export SUPABASE_URL=https://YOUR-PROJECT.supabase.co
export SUPABASE_KEY=sb_publishable_...      # or the legacy anon key. Never the secret/service_role key.
export USER_A_EMAIL=a@example.com USER_A_PASSWORD='...'
export USER_B_EMAIL=b@example.com USER_B_PASSWORD='...'

python3 rls_ab_test.py --table orders --table profiles:id --table messages:sender_id
python3 rls_ab_test.py --table orders --write --bucket avatars
```

`--table NAME:OWNER_COLUMN` sets the column that holds the owner's user id (default `user_id`).

Exit code `0` = no cross-user leak found, `1` = leak found, `2` = setup problem. Easy to drop into CI against a staging project.

Example output:

```
ok   notes: B can't read A's rows (B sees 1 row(s) total)
ok   notes: signed-out visitor reads nothing
OPEN orders: signed-out visitor can READ 2 row(s). Fine only if this table is meant to be public.
LEAK orders: B can READ 1 row(s) owned by A
LEAK orders: B can UPDATE 1 row(s) owned by A

2 leak(s) found.
```

## Safety

- Read-only unless you pass `--write`, and the write is a no-op (it sets a column to the value it already has).
- It refuses to run with an `sb_secret_` key, since secret keys bypass RLS and would make every test meaningless.
- Only run it against projects you own or have written permission to test.

## More

The full checklist (keys, `getClaims`/`getUser` vs `getSession`, storage, OAuth redirects, the referral-attribution bug) is here: [Supabase security checklist](https://madlouse.github.io/toolstack-lab/tools/supabase-audit-checklist.html).

If you'd rather have someone do it, there's a fixed-fee review described at the bottom of that page.

MIT licensed. Issues and PRs welcome.
