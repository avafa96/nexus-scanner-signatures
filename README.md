# Nexus official scanner signature producer

A narrowly scoped maintenance job for the existing private signature feed. This repository contains updater/transport code and synthetic tests only. It contains no business application, customer files, identities, deployment host access or credentials.

The job uses the pinned official ClamAV image and FreshClam. The exact `freshclam.dat` client identity and cooldown are restored before an attempt and preserved afterward, using the existing state archive format. CVD files are seeded from the pinned vendor image when present and updated by FreshClam; they are not duplicated in the private client-state archive. CVD signatures, age (maximum 24 hours), engine loading, a clean fixture and the standard harmless antivirus fixture are checked before publishing. A failed check does not publish a packet or reset the saved client state.

`NEXUS_SCANNER_FEED_CREDENTIAL` is a GitHub Actions secret for the existing service account, restricted to `official/*` in the existing private `nexus-scanner-signatures` bucket. It cannot access customer documents, application databases, identity providers or the host. No additional credentials or buckets are created.

Set `NEXUS_SCANNER_FEED_ENABLED=true` only after the connection is reviewed. Scheduling is every eight hours, with one non-overlapping producer. The existing server consumer, scanner engine and document acceptance policy remain authoritative and unchanged. Manual dispatch requires the exact source commit. There are no pull-request triggers or untrusted workflow inputs.

Standard GitHub-hosted runners in a public repository are free. This job creates no GitHub artifacts or caches, uses no larger runners and does not change any account plan or spending limit. An account-wide billing lock can still prevent execution; a successful run must be observed before this recovery can be accepted.

The business repository remains private. Never add customer data, secrets, generic remote execution, extra services or application release workflows here.

Persisted updater chunks are restored through sequential signed reads of at most 4 MiB. Each response must match the requested Content-Range and size, and complete chunk/archive hashes remain mandatory. Transfers have bounded connect, stall and total deadlines; interrupted reads never initialize a new updater state or discard cooldown.

Writes use at most 1 MiB per request to tolerate the existing network path. A synthetic 1 MiB upload/readback must pass before any vendor request. Packets remain limited to 160 MB, at most 160 content-bound chunks and a 64 KiB descriptor; the consumer verifies every part and the full archive before admission. The small client-state archive still preserves the exact updater identity and cooldown.
