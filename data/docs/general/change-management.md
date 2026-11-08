---
title: Making firewall rule changes safely
vendor: general
further_reading: NIST SP 800-41 Rev. 1, section on policy management (https://csrc.nist.gov/pubs/sp/800/41/r1/final)
---

# Making firewall rule changes safely

Written for fwlens in our own words. fwlens only ever proposes changes; a person reviews and applies them through the normal change process.

## Propose, review, apply

Every rule change should be written down as a proposal before it is applied: what changes, why, which traffic is affected, who owns it, and how to roll it back. A second person reviews the proposal against the current rulebase, because the most common firewall outage is a change that matches more or different traffic than its author expected.

## Check the impact before applying

Before adding or moving a rule, check which existing rules it would shadow or be shadowed by, and which logged sessions from the last few weeks it would have matched. Before removing a rule, confirm from logs or hit counters that it is not in use, and that its logging was enabled during the period you checked.

## Prefer disabling to deleting

When retiring a rule, disable it first and keep it for a quiet period, for example two to four weeks. If something breaks, re-enabling is a one-line, low-risk rollback. Delete the rule only after the quiet period passes without complaints.

## Narrow broad rules in steps

To tighten an any-any or otherwise broad rule, first add logging if it is missing, use the logs to find the sources, destinations and services that actually use the rule, create specific rules for that traffic above the broad rule, and then disable the broad rule. Watch the cleanup deny rule's logs for traffic that the new specific rules missed.

## Keep a record

Record every applied change with its ticket reference in the rule description or tags. The record lets future reviewers understand why a rule exists, which is what makes it safe to remove later.
