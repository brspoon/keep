# Third-party software and assets

Keep's own source is licensed under MIT. Dependencies retain their original
licenses and notices; installing the pinned distributions includes their metadata.
The container also includes Python and Alpine software with their own licenses.
Do not remove retained notices when redistributing images. OS and embedded-wheel
notices are retained under `/app/licenses`; installed Python and asset notices
remain in their original paths. Matching source and build materials are packaged
in versioned architecture-specific archives. See
[source distribution](docs/SOURCE_DISTRIBUTION.md) for matching-source downloads,
verification and retention requirements.

Direct runtime Python requirements are pinned in requirements.txt; transitive
distributions and OS packages must be inventoried from each built image. Before release,
generate an SBOM from each final image and review its full license inventory and
security scan. Package audits do not cover the container OS or image layers.
The [source distribution guide](docs/SOURCE_DISTRIBUTION.md#component-licenses-and-redistribution)
describes component licenses and delivery requirements; an SBOM alone does not
satisfy them.

Keep is an independent companion to Plex and Maintainerr. Their names identify
compatible services; their application code is not included. Service logo marks
are bundled locally as described below. Media artwork is fetched
from the operator's services at runtime. Do not use private library artwork in
public demos. Use synthetic data in examples and remove credentials and household
information from screenshots or logs before sharing them.

Maintainerr, Radarr, Sonarr and Tautulli logo marks come from the Homarr
Dashboard Icons collection. All four bundled files were verified byte for byte
against revision `638a84c865f3cdbab3a4b715c016f0543b1e530e` on 2026-09-30.
The collection's [Apache 2.0 license](https://github.com/homarr-labs/dashboard-icons/blob/638a84c865f3cdbab3a4b715c016f0543b1e530e/LICENSE),
including its copyright attribution, is retained in
`static/service-icons/dashboard-icons-LICENSE.txt` and included in the image.
That revision has no root NOTICE file. Sources and hashes are recorded in
[service icon provenance](static/service-icons/README.md). These unmodified marks
identify integrations; Keep is not endorsed by their owners. The collection
license does not grant trademark rights.

The Connections Plex wordmark is an unmodified SVG from the
[official Plex brand guide](https://brand.plex.tv/document/439975#/visual/logo),
retrieved on 2026-10-02. Its rendered size and surrounding space follow the
guide’s clear-space rule; it appears only to identify the connection.
Plex and the Plex logo are trademarks of Plex and used under a license.
See [Plex’s trademark guidelines](https://www.plex.tv/en-au/about/privacy-legal/plex-trademarks-and-guidelines/).
The original artwork URL and checksum are recorded in
[service icon provenance](static/service-icons/README.md).

The Connections Seerr logo mark is bundled from
[Seerr v3.4.1](https://github.com/seerr-team/seerr/blob/v3.4.1/public/os_icon.svg).
Its upstream MIT notice is retained in `static/service-icons/seerr-LICENSE.txt`.
The mark identifies the integration; Keep is not affiliated with Seerr.

The Dockerfile includes Alpine software, exact CPython security patches identified
in scripts/python_security_patches.json, and the signed Alpine zlib 1.3.2-r1
package. Python's license is retained in docs/PYTHON_LICENSE.txt; zlib's complete
license is retained with its verified upstream sources and OS notices.
The pinned urllib3 2.8.0 includes upstream response-framing correction
`5feb993421a48a508bc70c78e745337cc6415265`. Its original MIT notices and
source archive remain included, together with the exact patch, patched module
and a source hash checked against the installed module. Package version metadata
is unchanged. Python response framing includes upstream `2eb2af8` and the
`9f52b44` whitespace compatibility follow-up; exact commits and source hashes
are recorded with the runtime patch inputs.
The separately attributed Keep correction `keep-http-framing-bounds-v1`
limits padding to HTTP whitespace and preserves Python's handling of decimal
lengths exceeding its conversion limit. It is retained with the exact source
patches and is not attributed to an upstream commit.
The separately identified Expat build includes the exact upstream security
patches, the Keep-local literal-markup accounting correction, and the complete
MIT notice and source-header attributions. The local correction has its own
source identity in the retained patch manifest and source replay record; it is
not attributed to an upstream commit. Its build uses Alpine's verified Fortify
headers; their full 0BSD license, header attributions and matching source and
patch are included with the source materials and notices.
The build-only GNU Make and Bash inputs retain their complete GPL notices,
bundled component attributions, matching sources and Alpine recipes too.

The source map in `docs/os-package-sources.json` covers the final OS packages;
the original Expat, Python, zlib and CA bundle in earlier image layers are covered separately. Full notices,
source patches and recipes accompany the sources. Keep's source archive also
includes the Dockerfile and exact runtime patch/build scripts. Docker's signed
native build/source records are verified against actual APK hashes, with
upstream material hashes and full matching build contexts checked separately.
The narrowly scoped timezone and OpenSSL reconstructions record their different
evidence explicitly. Earlier layers' bundled pip/wheel and distlib launcher
sources and full notices are included too.
Source acquisition and notice packaging do not change repository visibility.
