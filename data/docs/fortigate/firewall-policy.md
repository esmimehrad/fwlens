---
title: FortiGate firewall policy best practices
vendor: fortigate
further_reading: Fortinet FortiGate / FortiOS documentation (https://docs.fortinet.com/product/fortigate); CIS Fortigate Benchmark (https://www.cisecurity.org/cis-benchmarks)
---

# FortiGate firewall policy best practices

Written for fwlens in our own words, summarising publicly documented Fortinet guidance. Check the vendor documentation for your FortiOS version.

## Policy order, not policy ID

FortiGate evaluates firewall policies from the top of the list down and uses the first match. The policy ID is only an identifier: a policy with ID 12 can sit above policy 10. When reasoning about shadowing or rule order, always use the position in the policy list, not the ID. Moving a policy changes its position but keeps its ID.

## Avoid all and ALL

The address object all matches every address and the service ALL matches every protocol and port. A policy with source all, destination all and service ALL allows everything between its interfaces. Use specific address objects or groups and named services, and restrict the source and destination interfaces to the ones the traffic really uses.

## Logging: all, utm and disable

The logtraffic setting controls traffic logging per policy. all logs every session; utm, the default, logs only sessions that trigger a security profile event, so ordinary allowed traffic may leave no log; disable logs nothing. For accept policies, prefer logtraffic all so that usage and investigations are not limited to sessions with security events. Treat accept policies with logging disabled as blind spots.

## The implicit deny

Traffic that matches no policy is dropped by the implicit deny, policy ID 0, which does not log by default. Enable logging for violation traffic, or add an explicit deny policy with logging at the bottom of the list, so blocked attempts are visible.

## Unused policies

FortiOS shows hit counts and last-used timestamps for each policy. Combine these with traffic logs to find unused policies. Remember that policies with logging disabled or set to utm may carry traffic that does not appear in traffic logs, so check the hit counter before concluding a policy is unused.

## Names and comments

Give every policy a name and use the comments field for the owner and change ticket. Unnamed policies appear in logs and reports only by their ID, which makes reviews slower and mistakes more likely.
