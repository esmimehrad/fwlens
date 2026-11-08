-- fwlens rule checks (Step 9).
--
-- FORMAT
--   Each check is one query under a "-- name: <check>" line. checks.py splits the file
--   on those lines. A check whose body is only comments counts as "not written yet".
--
-- CONTRACT (checks.py enforces it)
--   Every query returns exactly these columns, one row per finding:
--     rule_id          text      rules.id of the flagged rule
--     related_rule_id  text      the other rule involved (shadowed/duplicate), else NULL
--     detail           text      one human-readable sentence; shown to users and the agent
--   No parameters. Cover every loaded device, but never compare rules across devices
--   (same vendor AND device).
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
--
-- How: a plain filter on the rules table. 'any' is always stored alone, so comparing
-- the whole array to {'any'} is exact.
SELECT
    id AS rule_id,
    NULL::text AS related_rule_id,
    format(
        '%s allows traffic from any source to any destination on any service',
        name
    ) AS detail
FROM rules
WHERE enabled
  AND action = 'allow'
  AND src_addrs = ARRAY['any']
  AND dst_addrs = ARRAY['any']
  AND services = ARRAY['any']
ORDER BY vendor, device, position;


-- name: logging_off
-- Enabled allow rules with logging off (log = false).
--
-- How: a plain filter. Deny rules without logging aren't flagged: blocking quietly is
-- a choice, letting traffic in quietly leaves no audit trail.
SELECT
    id AS rule_id,
    NULL::text AS related_rule_id,
    format('%s allows traffic but logging is off, so its sessions leave no trace', name)
        AS detail
FROM rules
WHERE enabled
  AND action = 'allow'
  AND NOT log
ORDER BY vendor, device, position;


-- name: duplicate
-- Pairs of rules on the same device whose match fields are all identical: src_zones,
-- dst_zones, src_addrs, dst_addrs, services, applications, compared as SETS (order
-- doesn't matter). Action and enabled state don't matter.
-- rule_id = the later rule (higher position), related_rule_id = the earliest identical
-- rule, so three copies of a rule give two findings, both pointing at the original.
--
-- How: join rules to earlier rules on the same device. Two arrays are equal as sets
-- when each contains the other: a @> b AND a <@ b (ignores order and repeats).
-- DISTINCT ON keeps only the earliest match for each later rule.
SELECT DISTINCT ON (later.id)
    later.id AS rule_id,
    earlier.id AS related_rule_id,
    format(
        '%s matches exactly the same traffic as %s (position %s), which comes first',
        later.name, earlier.name, earlier.position
    ) AS detail
FROM rules AS later
JOIN rules AS earlier
  ON earlier.vendor = later.vendor
 AND earlier.device = later.device
 AND earlier.position < later.position
WHERE earlier.src_zones    @> later.src_zones    AND earlier.src_zones    <@ later.src_zones
  AND earlier.dst_zones    @> later.dst_zones    AND earlier.dst_zones    <@ later.dst_zones
  AND earlier.src_addrs    @> later.src_addrs    AND earlier.src_addrs    <@ later.src_addrs
  AND earlier.dst_addrs    @> later.dst_addrs    AND earlier.dst_addrs    <@ later.dst_addrs
  AND earlier.services     @> later.services     AND earlier.services     <@ later.services
  AND earlier.applications @> later.applications AND earlier.applications <@ later.applications
ORDER BY later.id, earlier.position;


-- name: shadowed
-- An enabled rule that can never match because an EARLIER enabled rule on the same
-- device covers all of its traffic: on every one of the six match fields, the later
-- rule's values are a subset of the earlier rule's ('any' covers everything).
-- Action doesn't matter: whatever the earlier rule does, the later rule never runs.
-- Exact duplicates are reported by the duplicate check, so they're excluded here.
-- rule_id = the shadowed (later) rule, related_rule_id = the earliest covering rule.
--
-- How, in three steps:
--   1. rule_values: one row per (rule, field, value), with address and service names
--      expanded to what they resolve to. Unresolved group members are kept as names,
--      so a rule pointing at something missing is never treated as fully covered.
--   2. covered: for each later/earlier pair on the same device, "no value of the later
--      rule is left uncovered by the earlier rule in the same field" (a double NOT
--      EXISTS: SQL's way of saying "for all").
--   3. Keep the earliest covering rule per shadowed rule, minus exact duplicates.
--
-- A value is covered by an earlier value when the earlier one is 'any', the two are
-- equal, or both are IP networks and the later one sits inside the earlier one
-- (inet <<=). Limitation: ip-range and fqdn values only match by exact string, so a
-- host inside an earlier ip-range is not detected.
WITH rule_values AS (
    SELECT r.id, f.field, v.value
    FROM rules AS r
    CROSS JOIN LATERAL (VALUES
        ('src_zones', r.src_zones),
        ('dst_zones', r.dst_zones),
        ('src_addrs', r.src_addrs),
        ('dst_addrs', r.dst_addrs),
        ('services', r.services),
        ('applications', r.applications)
    ) AS f(field, names)
    CROSS JOIN LATERAL unnest(f.names) AS n(name)
    LEFT JOIN address_objects AS a
      ON f.field IN ('src_addrs', 'dst_addrs') AND n.name <> 'any'
     AND a.vendor = r.vendor AND a.device = r.device AND a.name = n.name
    LEFT JOIN service_objects AS s
      ON f.field = 'services' AND n.name <> 'any'
     AND s.vendor = r.vendor AND s.device = r.device AND s.name = n.name
    -- resolved values plus any unresolved member names; fall back to the name itself
    -- (zones, applications, 'any', 'application-default', unknown objects)
    CROSS JOIN LATERAL unnest(
        COALESCE(
            NULLIF(a.resolved || a.unresolved, '{}'),
            NULLIF(s.resolved || s.unresolved, '{}'),
            ARRAY[n.name]
        )
    ) AS v(value)
    WHERE r.enabled
),
covered AS (
    SELECT later.id AS later_id, earlier.id AS earlier_id, earlier.position
    FROM rules AS later
    JOIN rules AS earlier
      ON earlier.vendor = later.vendor
     AND earlier.device = later.device
     AND earlier.position < later.position
    WHERE later.enabled
      AND earlier.enabled
      AND NOT EXISTS (
          SELECT 1
          FROM rule_values AS lv
          WHERE lv.id = later.id
            AND NOT EXISTS (
                SELECT 1
                FROM rule_values AS ev
                WHERE ev.id = earlier.id
                  AND ev.field = lv.field
                  AND (
                      ev.value = 'any'
                      OR ev.value = lv.value
                      -- CASE guarantees the cast only runs on values that look like IPs
                      -- (an fqdn or ip-range would make ::inet fail)
                      OR CASE
                          WHEN lv.field IN ('src_addrs', 'dst_addrs')
                           AND lv.value ~ '^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:.]*)(/\d{1,3})?$'
                           AND ev.value ~ '^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:.]*)(/\d{1,3})?$'
                          THEN lv.value::inet <<= ev.value::inet
                          ELSE false
                      END
                  )
            )
      )
),
duplicates AS (
    SELECT later.id
    FROM rules AS later
    JOIN rules AS earlier
      ON earlier.vendor = later.vendor
     AND earlier.device = later.device
     AND earlier.position < later.position
    WHERE earlier.src_zones    @> later.src_zones    AND earlier.src_zones    <@ later.src_zones
      AND earlier.dst_zones    @> later.dst_zones    AND earlier.dst_zones    <@ later.dst_zones
      AND earlier.src_addrs    @> later.src_addrs    AND earlier.src_addrs    <@ later.src_addrs
      AND earlier.dst_addrs    @> later.dst_addrs    AND earlier.dst_addrs    <@ later.dst_addrs
      AND earlier.services     @> later.services     AND earlier.services     <@ later.services
      AND earlier.applications @> later.applications AND earlier.applications <@ later.applications
)
SELECT DISTINCT ON (c.later_id)
    c.later_id AS rule_id,
    c.earlier_id AS related_rule_id,
    format(
        '%s can never match: earlier rule %s (position %s) already covers all of its traffic',
        later.name, earlier.name, c.position
    ) AS detail
FROM covered AS c
JOIN rules AS later ON later.id = c.later_id
JOIN rules AS earlier ON earlier.id = c.earlier_id
WHERE c.later_id NOT IN (SELECT id FROM duplicates)
ORDER BY c.later_id, c.position;


-- name: zero_hit
-- Enabled rules with no rows in log_events (match on vendor, device, rule_name = name).
-- Rules with logging off produce no logs even when they carry traffic: still report
-- them, but their detail says that logging is off, so "zero hits" isn't read as
-- "unused".
--
-- How: NOT EXISTS against log_events. Devices with no logs loaded at all are skipped:
-- with no data, every rule would look unused, which says nothing about the rules.
SELECT
    r.id AS rule_id,
    NULL::text AS related_rule_id,
    CASE
        WHEN r.log THEN format('%s has no hits in the loaded logs', r.name)
        ELSE format(
            '%s has no hits in the loaded logs, but logging is off for this rule, '
            'so it may still be carrying traffic',
            r.name
        )
    END AS detail
FROM rules AS r
WHERE r.enabled
  AND EXISTS (
      SELECT 1 FROM log_events AS e
      WHERE e.vendor = r.vendor AND e.device = r.device
  )
  AND NOT EXISTS (
      SELECT 1 FROM log_events AS e
      WHERE e.vendor = r.vendor AND e.device = r.device AND e.rule_name = r.name
  )
ORDER BY r.vendor, r.device, r.position;
