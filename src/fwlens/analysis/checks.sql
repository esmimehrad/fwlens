-- fwlens rule checks. Written by Mehrad (Step 9); see CLAUDE.md.
--
-- FORMAT
--   Each check is one query under a "-- name: <check>" line. checks.py splits the file
--   on those lines. A check with an empty body counts as "not written yet": the runner
--   skips it and its tests are skipped, so CI stays green while you work.
--
-- CONTRACT (checks.py enforces it)
--   Every query returns exactly these columns, one row per finding:
--     rule_id          text      rules.id of the flagged rule
--     related_rule_id  text      the other rule involved (shadowed/duplicate), else NULL
--     detail           text      one human-readable sentence; shown to users and the agent
--   No parameters. Cover every loaded device, but never compare rules across devices
--   (same vendor AND device). A trailing semicolon is fine.
--
-- TABLES (src/fwlens/db/schema.py)
--   rules(id, vendor, device, name, position, vendor_id, src_zones[], dst_zones[],
--         src_addrs[], dst_addrs[], services[], applications[], action, enabled, log,
--         hit_count)
--   address_objects(vendor, device, name, kind, value, members[], resolved[], unresolved[])
--   service_objects(vendor, device, name, is_group, entries[], members[], resolved[],
--                   unresolved[])
--   log_events(vendor, device, ts, src_ip inet, dst_ip inet, dst_port, protocol,
--              rule_name, action, bytes)
--   "Match everything" is always stored as the single value 'any'.
--
-- GROUND TRUTH: evals/cases/seeded_flaws.json lists exactly what each check must find
-- on the sample data. Run: uv run pytest tests/test_checks.py -v


-- name: any_any
-- Enabled allow rules where source addresses, destination addresses AND services are
-- all 'any'. (Zones and applications don't matter here.)


-- name: logging_off
-- Enabled allow rules with logging off (log = false).


-- name: duplicate
-- Pairs of rules on the same device whose match fields are all identical: src_zones,
-- dst_zones, src_addrs, dst_addrs, services, applications, compared as SETS (order
-- doesn't matter). Action and enabled state don't matter.
-- rule_id = the later rule (higher position), related_rule_id = the earlier one.
-- Report each pair once.


-- name: shadowed
-- An enabled rule that can never match because an EARLIER enabled rule on the same
-- device covers all of its traffic: on every one of the six match fields, the later
-- rule's values are a subset of the earlier rule's ('any' covers everything).
-- Action doesn't matter: whatever the earlier rule does, the later rule never runs.
--   - Addresses: compare what the names resolve to (address_objects.resolved), so a
--     host inside an earlier group or subnet counts as covered. CIDR containment is
--     required; ip-range and fqdn values may be compared by exact string match
--     (document that limitation in your detail or a comment).
--   - Services: compare resolved entries (service_objects.resolved); names that aren't
--     service objects ('application-default') compare by name.
--   - Zones and applications: compare by name.
-- Exact duplicates are reported by the duplicate check, so exclude them here.
-- rule_id = the shadowed (later) rule, related_rule_id = the earliest covering rule.


-- name: zero_hit
-- Enabled rules with no rows in log_events (match on vendor, device, rule_name = name).
-- Rules with logging off produce no logs even when they carry traffic: still report
-- them, but their detail must say that logging is off, so "zero hits" isn't read as
-- "unused".
