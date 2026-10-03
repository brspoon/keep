# Supplemental dependency notices

These files supplement the notices retained by installed Python distributions.
They preserve the original bytes from the sources below; they do not replace
the dependency notices or the matching source bundle.

`os/` contains full notices obtained from matching package sources, plus a
provenance inventory that maps each retained notice to its package and source
path, including original Expat and bundled pip/wheel notices from earlier layers.
The inventory explicitly records reviewed source copyright headers, including
CA certificates, SQLite, GCC runtime libraries, libuuid and musl subcomponents.
Standalone upstream license texts remain complete. The native image copies this
directory to `/app/licenses/os`. See
[source distribution](../SOURCE_DISTRIBUTION.md) for the versioned source,
recipe and patch archives and the remaining public delivery requirement.

| File | Matching component and source | SHA-256 |
| --- | --- | --- |
| `ARGON2_LICENSE.txt` | `extras/libargon2/LICENSE` in the [argon2-cffi-bindings 26.1.0 source archive](https://files.pythonhosted.org/packages/0b/43/bb8b6e8708d49a5ab36781333af092d9f483b198a2710d01281204640055/argon2_cffi_bindings-26.1.0.tar.gz) | `ac36638bcfcedb75441a5daeeaf4ef75b565911712583c272830e9fa7fddb590` |
| `CFFI_LIBFFI_LICENSE.txt` | `LICENSE` in the [libffi 3.4.6 source archive](https://github.com/libffi/libffi/archive/v3.4.6.tar.gz), statically embedded by CFFI's Linux wheel build | `67894089811f93fca47a76f85e017da6f8582d4ba0905963c6e0f1ad6df7a195` |
| `MPL-2.0.txt` | [Mozilla's complete MPL 2.0 license](https://www.mozilla.org/media/MPL/2.0/index.815ca599c9df.txt), supplementing certifi and the reviewed CA certificate source's MPL notices | `fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85` |
| `GPL-2.0-only.txt` | Complete GNU GPL version 2, verified against [GNU GCC's pinned COPYING](https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=COPYING;hb=0063a8238d6f2b3cb933cffb33a0b69abfa90674) and its repository mirror; supplements the reviewed alpine-baselayout recipe's GPL-2.0-only declaration | `231f7edcc7352d7734a96eef0b8030f77982678c516876fcb81e25b32d68564c` |

Argon2's reference implementation is available under CC0-1.0 or Apache-2.0.
Its complete upstream notice retains both license texts and names Daniel Dinu,
Dmitry Khovratovich, Jean-Philippe Aumasson and Samuel Neves. The bindings'
separate MIT notice remains installed. The exact source archive has SHA-256
`63505c71542a44b68b1e38060450fb006404170da375feb31af153e7f9c6205d` and includes
the reference implementation, its BLAKE2 code and the CMake build recipe.

CFFI 2.1.1's [versioned upstream wheel build recipe](https://github.com/python-cffi/cffi/blob/fd33e7700f0ebafe6f30bd5053f13327221b77a2/.github/workflows/ci.yaml)
downloads libffi 3.4.6, enables position-independent code, disables shared
libraries and builds with `-Dffi_call=cffistatic_ffi_call`. This recipe applies
to both the x86_64 and aarch64 musllinux wheel jobs. Both reviewed CPython 3.14
wheels depend on musl and have no dynamic libffi dependency. Their embedded
libffi is separate from the base image's installed libffi package.

The libffi source archive has SHA-256
`9ac790464c1eb2f5ab5809e978a1683e9393131aede72d1b0a0703771d3c6cda`.
The retained wheel build recipe has SHA-256
`b1910ddbfc69d2fbe41f1493cb564658d0970522bfeb5e6fe93d3288c802736c` and comes
from CFFI release commit `fd33e7700f0ebafe6f30bd5053f13327221b77a2`.
Keep's source bundle retains these materials alongside the exact Python source
archives and per-architecture wheel identities.

The certifi 2026.7.22 source archive retains its exact `cacert.pem`, MPL notice
and build files. Its SHA-256 is
`741e2c3b351ddf169a738da9f2c048608ff7f2c5cc02f1ebc6b118bb090d5d55`.
Providing the complete MPL text does not itself provide the matching source;
the versioned source archive remains part of the distribution materials.
