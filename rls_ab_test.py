#!/usr/bin/env python3
"""rls_ab_test.py: two-account Row Level Security check for a Supabase project.

Signs in as user A and user B with the public (publishable / anon) key, then asks:
  * Can B read rows that belong to A?
  * Can a signed-out visitor read anything?
  * (opt-in, --write) Can B update A's rows? Uses a no-op update that writes the
    owner column back to its current value, so no data changes even if it succeeds.
  * (optional, --bucket) Can B list A's files in a storage bucket?

Read-only by default. Standard library only (Python 3.8+). Run it against staging
or with throwaway test accounts. Never run it against a project you don't own.

Usage:
  export SUPABASE_URL=https://xyz.supabase.co
  export SUPABASE_KEY=sb_publishable_...        # or the legacy anon key
  export USER_A_EMAIL=a@example.com USER_A_PASSWORD=...
  export USER_B_EMAIL=b@example.com USER_B_PASSWORD=...
  python3 rls_ab_test.py --table profiles:id --table orders --table messages:sender_id
  python3 rls_ab_test.py --table orders --write --bucket avatars

--table NAME[:OWNER_COLUMN]  OWNER_COLUMN defaults to user_id.
Exit code: 0 = no cross-user leak found, 1 = leak found, 2 = setup error.
Tables a signed-out visitor can read are printed as OPEN (a warning, not a leak).
"""
import argparse, json, os, sys, urllib.error, urllib.parse, urllib.request

def die(msg):
    print("setup error: " + msg, file=sys.stderr)
    sys.exit(2)

def req(method, url, key, token=None, body=None, extra=None):
    h = {"apikey": key, "Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    elif key.startswith("eyJ"):          # legacy anon key is a JWT
        h["Authorization"] = "Bearer " + key
    if extra:
        h.update(extra)
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            raw = resp.read().decode() or "null"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw

def sign_in(base, key, email, password, label):
    st, js = req("POST", base + "/auth/v1/token?grant_type=password", key,
                 body={"email": email, "password": password})
    if st != 200 or not isinstance(js, dict) or "access_token" not in js:
        die("could not sign in as %s (HTTP %s): %s" % (label, st, js))
    return js["access_token"], js["user"]["id"]

def select(base, key, token, table, limit):
    q = urllib.parse.urlencode({"select": "*", "limit": str(limit)})
    return req("GET", "%s/rest/v1/%s?%s" % (base, urllib.parse.quote(table), q), key, token)

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", action="append", required=True, help="NAME[:OWNER_COLUMN]")
    ap.add_argument("--write", action="store_true", help="also try a no-op UPDATE of A's rows as B")
    ap.add_argument("--bucket", action="append", default=[], help="storage bucket to check (files under <A's user id>/)")
    ap.add_argument("--limit", type=int, default=1000)
    a = ap.parse_args()

    env = {k: os.environ.get(k) for k in ("SUPABASE_URL", "SUPABASE_KEY", "USER_A_EMAIL",
                                          "USER_A_PASSWORD", "USER_B_EMAIL", "USER_B_PASSWORD")}
    missing = [k for k, v in env.items() if not v]
    if missing:
        die("missing env vars: " + ", ".join(missing))
    base, key = env["SUPABASE_URL"].rstrip("/"), env["SUPABASE_KEY"]
    if key.startswith("sb_secret_"):
        die("that is a secret key, which bypasses RLS. Use the publishable or anon key.")

    tok_a, id_a = sign_in(base, key, env["USER_A_EMAIL"], env["USER_A_PASSWORD"], "A")
    tok_b, id_b = sign_in(base, key, env["USER_B_EMAIL"], env["USER_B_PASSWORD"], "B")
    if id_a == id_b:
        die("A and B are the same user")
    print("A = %s\nB = %s\n" % (id_a, id_b))

    leaks, notes, public = [], [], []
    for spec in a.table:
        table, _, owner = spec.partition(":")
        owner = owner or "user_id"
        st_a, rows_a = select(base, key, tok_a, table, a.limit)
        if st_a != 200 or not isinstance(rows_a, list):
            notes.append("%s: A can't read the table (HTTP %s). Check the name, or it's blocked for everyone." % (table, st_a))
            continue
        a_owned = [r for r in rows_a if str(r.get(owner)) == id_a]
        if rows_a and owner not in rows_a[0]:
            notes.append("%s: column '%s' not in rows; pass --table %s:<owner column>" % (table, owner, table))
            continue
        if not a_owned:
            notes.append("%s: A owns no rows, so the cross-user read test proves nothing. Create one row as A first." % table)

        st_b, rows_b = select(base, key, tok_b, table, a.limit)
        b_sees_a = [r for r in rows_b if str(r.get(owner)) == id_a] if isinstance(rows_b, list) else []
        if b_sees_a:
            leaks.append("%s: B can READ %d row(s) owned by A" % (table, len(b_sees_a)))
        else:
            print("ok   %s: B can't read A's rows (B sees %s row(s) total)" % (table, len(rows_b) if isinstance(rows_b, list) else "HTTP %s" % st_b))

        st_n, rows_n = select(base, key, None, table, a.limit)
        if isinstance(rows_n, list) and rows_n:
            public.append("%s: signed-out visitor can READ %d row(s). Fine only if this table is meant to be public." % (table, len(rows_n)))
        else:
            print("ok   %s: signed-out visitor reads nothing" % table)

        if a.write and a_owned:
            url = "%s/rest/v1/%s?%s=eq.%s" % (base, urllib.parse.quote(table), urllib.parse.quote(owner), urllib.parse.quote(id_a))
            st_u, rows_u = req("PATCH", url, key, tok_b, body={owner: id_a}, extra={"Prefer": "return=representation"})
            # A blocked UPDATE usually returns 200 with zero rows, so count rows, not the status code.
            if isinstance(rows_u, list) and rows_u:
                leaks.append("%s: B can UPDATE %d row(s) owned by A" % (table, len(rows_u)))
            else:
                print("ok   %s: B's update of A's rows touched 0 rows (HTTP %s)" % (table, st_u))

    for bucket in a.bucket:
        st_s, objs = req("POST", "%s/storage/v1/object/list/%s" % (base, urllib.parse.quote(bucket)), key, tok_b,
                         body={"prefix": id_a, "limit": 100})
        if isinstance(objs, list) and objs:
            leaks.append("storage/%s: B can LIST %d object(s) under A's folder" % (bucket, len(objs)))
        else:
            print("ok   storage/%s: B can't list A's folder (HTTP %s, %s item(s))" % (bucket, st_s, len(objs) if isinstance(objs, list) else 0))

    print()
    for n in notes:
        print("note " + n)
    for w in public:
        print("OPEN " + w)
    for l in leaks:
        print("LEAK " + l)
    print("\n%d leak(s) found." % len(leaks) if leaks else "\nNo leaks found in what was tested. Not tested: DELETE, INSERT with A's id, RPC functions, Edge Functions.")
    sys.exit(1 if leaks else 0)

if __name__ == "__main__":
    main()
