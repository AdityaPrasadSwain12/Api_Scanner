# Third-party notices

Reviewed 2026-09-13 against the upstream project/release pages. This inventory is engineering documentation, not legal advice. Re-check licenses, image contents, transitive packages, trademarks, export controls, and current releases before commercial distribution.

| Component | Pinned version | License | How used | Commercial SaaS / redistribution notes |
|---|---:|---|---|---|
| OWASP ZAP | 2.17.0 | Apache-2.0 | Separate official daemon container | Commercial use and redistribution are permitted under Apache-2.0; retain license/notices and mark modifications. ZAP/OWASP names remain subject to trademark rules. |
| Nuclei | 3.11.0 | MIT | Binary copied from official image into isolated runner | Commercial use and redistribution are permitted; retain copyright and license notice. |
| nuclei-templates | 10.4.7 | MIT (repository) | Pinned, controlled directories copied into Nuclei runner | Treat templates as a separately versioned component; retain MIT notice and re-review contributed/template-specific material on update. User templates are not accepted. |
| Wfuzz | 3.1.1 | GPL-2.0-only (upstream metadata/repository) | Installed in a separate isolated runner image | Network use alone is generally distinct from distribution. If distributing the runner image, provide the GPL license and complete corresponding source/valid source offer as applicable, including modifications. Obtain counsel for the chosen distribution model. |
| WuppieFuzz | 1.7.1 | Apache-2.0 | Built from pinned source in a separate runner image | Commercial use/distribution permitted subject to Apache-2.0 notices and modification markings. Upstream includes its own third-party notices/SBOM; preserve them in distributed images. |
| PostgreSQL | 17.6 | PostgreSQL License | Separate database container | Commercial use/distribution permitted; retain required copyright/license paragraphs. |
| Valkey | 9.1.1 | BSD-3-Clause | Redis-protocol queue/backend container | Commercial use/distribution permitted; retain source/binary notices and do not imply endorsement. Chosen instead of Redis 7.4+, whose license requires separate product review. |
| FastAPI | 0.116.1 | MIT | Linked Python dependency | Retain MIT copyright/license in distributions. |
| Celery | 5.5.3 | BSD-3-Clause | Linked Python dependency | Retain BSD copyright/license; no endorsement. Celery documentation has a separate CC BY-SA license. |
| SQLAlchemy | 2.0.43 | MIT | Linked Python dependency | Retain MIT copyright/license in distributions. |
| Pydantic / pydantic-settings | 2.11.x / 2.10.1 | MIT | Linked Python dependencies | Retain MIT copyright/license in distributions. |
| HTTPX | 0.28.1 | BSD-3-Clause | Linked Python dependency | Retain BSD copyright/license; no endorsement. |
| cryptography | 46.0.1 | Apache-2.0 OR BSD-3-Clause | Linked Python dependency | Comply with the selected license and bundled OpenSSL/Rust dependency notices. |
| ReportLab | 4.4.3 | BSD-style | Linked Python dependency | Retain upstream license/copyright notices. |

Upstream sources and license locations are recorded in [LICENSES/README.md](LICENSES/README.md). The repository does not copy third-party scanner source. Docker builds retrieve official binaries or pinned source and execute them as separate processes/services.

Wfuzz distribution deserves special attention: this project is Apache-2.0, while the Wfuzz runner contains a GPL-2.0-only program. Keeping it process- and container-separated avoids copying its code into the application, but distributing the combined delivery can still create notice/source obligations. Do not claim compliance without reviewing the actual shipped artifacts and delivery model.

