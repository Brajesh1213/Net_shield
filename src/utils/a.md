Default deny (nothing trusted by default)

Verify process identity (real signer CN, not hardcoded)

Verify file identity (SHA-256 + file ID)

Canonical path check (GetFinalPathNameByHandleW)

Block reparse points / symlinks / junctions

Verify process token SID (SYSTEM / Admin / User)

Verify loaded DLLs (all signed & trusted)

Continuous verification (re-check on every connection/event)

Short-TTL trust caching (trust expires automatically)

Policy-driven allowlist (publisher / hash / path)

Tamper protection (SYSTEM service, locked registry ACLs)

Fail-secure behavior (verification fails → deny)

Network enforcement (WFP / kernel, not user-mode only)

Audit logging (who, what, when, why)

Alerting on disable / bypass attempts

No silent failures

Privilege-aware decisions (user vs admin vs SYSTEM)

Module injection detection

Policy integrity (signed rules)

Assume breach always
