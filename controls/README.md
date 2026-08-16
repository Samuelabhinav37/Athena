# Continuous control mappings

This directory contains machine-readable mappings from Athena's executable evidence to NIST SP 800-53 controls.

Current scope:

- AC-2 — Account Management
- AC-5 — Separation of Duties
- AC-6 — Least Privilege

A `partial` status means Athena has relevant automated evidence but does not yet implement every part of the control. The security gate validates that referenced Rego rules, policy fixtures, and test files still exist. These mappings support continuous evidence; they are not by themselves a compliance certification.
