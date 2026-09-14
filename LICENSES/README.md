# License source inventory

Exact upstream license texts must be retained in produced container/application distributions. Authoritative locations reviewed on 2026-09-13:

- OWASP ZAP 2.17.0 — Apache-2.0: https://github.com/zaproxy/zaproxy/blob/v2.17.0/LICENSE
- Nuclei 3.11.0 — MIT: https://github.com/projectdiscovery/nuclei/blob/v3.11.0/LICENSE.md
- Nuclei templates 10.4.7 — MIT: https://github.com/projectdiscovery/nuclei-templates/blob/v10.4.7/LICENSE.md
- Wfuzz 3.1.1 — GPL-2.0-only: https://github.com/xmendez/wfuzz/blob/v3.1.1/LICENSE
- WuppieFuzz 1.7.1 — Apache-2.0: https://github.com/TNO-S3/WuppieFuzz/blob/v1.7.1/LICENSE
- WuppieFuzz transitive notices: https://github.com/TNO-S3/WuppieFuzz/blob/v1.7.1/THIRD_PARTY_NOTICES
- PostgreSQL — PostgreSQL License: https://www.postgresql.org/about/licence/
- Valkey 9.1.1 — BSD-3-Clause: https://github.com/valkey-io/valkey/blob/9.1.1/COPYING
- Celery 5.5.3 — BSD-3-Clause: https://github.com/celery/celery/blob/v5.5.3/LICENSE

Run `pip-licenses --format=json --with-urls --with-license-file` in the final application image and Syft against every produced image to generate the release-specific complete inventory. The CycloneDX file under `SBOM/` records the direct design-time components and is not a replacement for release-image SBOMs.

