---
title: PAN-OS security policy best practices
vendor: panos
further_reading: Palo Alto Networks PAN-OS documentation and best-practice guides (https://docs.paloaltonetworks.com/); CIS Palo Alto Firewall Benchmark (https://www.cisecurity.org/benchmark/palo_alto_networks)
---

# PAN-OS security policy best practices

Written for fwlens in our own words, summarising publicly documented Palo Alto Networks guidance. Check the vendor documentation for your PAN-OS version.

## Use App-ID with application-default

PAN-OS identifies applications from the traffic itself (App-ID) rather than trusting the port. Allow rules should name specific applications and set the service to application-default, which restricts each application to its standard ports. A rule that allows an application on service any lets that application run on any port, which is a common way for unwanted traffic to blend in. Avoid allow rules with application any except where there is a documented reason.

## Avoid any in source, destination and service

Rules with any in the source address, destination address and service fields are effectively open. Use address objects or groups for sources and destinations, and limit zones to the ones the traffic really crosses. A rule from the untrust zone with destination any is especially risky because it exposes everything behind the firewall in the destination zone.

## Log at session end

Enable Log at Session End on every allow rule. Session-end logs contain the application, bytes transferred and session duration, which are needed for investigations and for usage analysis. Session-start logging is rarely needed and generates extra volume; if it is enabled, count each session once when analysing usage.

## Rule usage and hit counts

PAN-OS tracks hit counts and first/last hit timestamps for each security rule, and the Policy Optimizer feature reports unused rules and rules that could be converted from port-based to application-based. Use these together with traffic logs when reviewing rules. Hit counts reset on some events, so check when the counter last reset before trusting a zero.

## Rule ordering and the default rules

PAN-OS evaluates security rules top-down. Two predefined rules sit at the bottom: intrazone-default (allow) and interzone-default (deny), and neither logs by default. Override interzone-default to enable logging, or add an explicit deny-all rule with logging above it so that denied traffic is visible.

## Tags, descriptions and UUIDs

Every rule has a UUID that stays stable across renames, which makes it a better reference than the name in change tickets and external tools. Use tags and the description field to record the owner and the ticket for each rule.
