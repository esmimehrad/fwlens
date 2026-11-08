---
title: Firewall rulebase hygiene
vendor: general
further_reading: NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy (https://csrc.nist.gov/pubs/sp/800/41/r1/final); CIS Benchmarks for firewall platforms (https://www.cisecurity.org/cis-benchmarks)
---

# Firewall rulebase hygiene

Written for fwlens in our own words, summarising widely published firewall policy guidance.

## Why rulebase hygiene matters

A firewall rulebase grows by accretion: every project, incident and vendor request adds rules, and few are ever removed. Over time the rulebase stops describing the intended policy. Unused, overlapping and overly broad rules increase attack surface, slow down audits, and make every change riskier because nobody is sure what a rule still does. Regular hygiene reviews keep the rulebase small enough to reason about.

## Overly permissive rules (any-any)

A rule that allows any source to any destination on any service effectively turns the firewall off for the zones it covers. These rules usually start as temporary troubleshooting or vendor-access rules and are never removed. Every allow rule should name the narrowest sources, destinations and services that the business need requires. If a broad rule is unavoidable for a short period, give it an owner, a ticket reference and an expiry date, and review it at that date.

## Shadowed rules

Firewalls evaluate rules top-down and stop at the first match. A rule is shadowed when an earlier rule matches all of the traffic it would match, so it can never take effect. Shadowed rules are dangerous in two directions: an administrator may believe a restrictive rule is protecting a server when an earlier broad allow is actually handling the traffic, or a needed allow may never fire because of an earlier deny. Fix shadowing by deleting the shadowed rule if it is redundant, or by moving a more specific rule above the broader one if the specific behaviour is what was intended.

## Duplicate rules

Duplicate rules match exactly the same traffic. Only the first one ever takes effect, so later copies are dead weight that confuse reviewers and can be edited by mistake. Remove the later copy after confirming that its action, logging and security profiles add nothing the first rule lacks.

## Unused rules and hit counts

Rules with no hits over a representative period (commonly 90 days, covering month-end and quarterly cycles) are candidates for removal. Before removing one, confirm three things: that logging or hit counting was actually enabled for the rule during that period, that the observation window covers rare but legitimate traffic such as disaster-recovery tests or annual batch jobs, and that the rule's owner agrees. Disable the rule first and delete it after a further quiet period, so the change is easy to roll back.

## Rule ordering

Put the most specific rules first and broader rules later, with an explicit cleanup rule at the end that denies and logs everything else. Place frequently matched rules reasonably high so that rule lookups stay efficient, but never move a rule above another if that would change which traffic each one matches.

## Documentation and ownership

Every rule should carry a description, an owning team or person, and the change ticket that created it. Rules without an owner are the hardest to remove safely, so require ownership at creation time. Periodic recertification, where owners confirm their rules are still needed, keeps the rulebase aligned with the business.
