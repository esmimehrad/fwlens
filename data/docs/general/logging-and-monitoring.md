---
title: Firewall logging and monitoring
vendor: general
further_reading: NIST SP 800-92, Guide to Computer Security Log Management (https://csrc.nist.gov/pubs/sp/800/92/final); NIST SP 800-41 Rev. 1 (https://csrc.nist.gov/pubs/sp/800/41/r1/final)
---

# Firewall logging and monitoring

Written for fwlens in our own words, summarising widely published logging guidance.

## Log allowed traffic, not only denied traffic

Logging only denied traffic shows what was blocked but not what got through. During an incident, investigators need to know which sessions a compromised host opened, and that information only exists if allow rules log. Every allow rule should log at least at session end, which records the final byte counts and duration of each session. Rules that allow traffic without logging are blind spots and should be the exception, justified and documented.

## Log the default deny

Most firewalls end the rulebase with an implicit deny that does not log by default. Add an explicit final deny rule with logging enabled so that blocked attempts are visible. This is often the first place scanning and misconfigured applications show up.

## Zero hits do not always mean unused

A rule with no entries in the traffic logs may still be carrying traffic if its logging is disabled, if logs are sampled or filtered before they reach the collector, or if the observation window is too short. Before calling a rule unused, check that the rule logs, that the log pipeline receives that device's traffic logs, and that the time window is long enough. Device-side hit counters, where available, are a useful second source because they count matches even when logging is off.

## Retention and time synchronisation

Keep traffic logs long enough to support investigations and hit-count reviews; 90 days of searchable logs is a common minimum, with longer archival storage. Synchronise every firewall to the same time source (NTP) and record time zones explicitly, otherwise correlating events across devices becomes unreliable.

## Forward logs off the device

Firewalls have limited local storage and an attacker with administrative access can clear local logs. Forward logs to a central collector or SIEM over a reliable transport, and alert when a device stops sending logs, because silence is itself a signal.
