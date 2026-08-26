# Supply-chain controls

The `Athena Supply Chain` workflow runs independently of the functional security gate. It audits the
installed Python dependency graph against published advisories, generates a CycloneDX JSON SBOM,
builds both runtime images, fails on fixable high or critical image findings, and records SHA-256
digests for the uploaded evidence bundle. Unfixed base-distribution findings remain visible in scan
output and require the documented exception or base-image refresh process before promotion.

Analysis tools are CI-only and exactly versioned; they are not Athena runtime dependencies. GitHub
Actions are pinned by commit. Release promotion must retain the workflow run URL, SBOM, digest
manifest, source commit, and image digests together. A vulnerability exception requires an owner,
expiry, compensating control, and review reference; changing the workflow to ignore a finding is not
an exception process.
