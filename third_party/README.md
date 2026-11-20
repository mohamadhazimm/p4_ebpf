# Third-party code

Code that this project uses but did not write. Each part keeps its own license, and this repository's `LICENSE` does
not apply to it.

| Path | What | License |
|---|---|---|
| `libbpf-bootstrap/` | [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap), vendored on 2026-10-12 with its submodules as plain files: `libbpf/`, `bpftool/`, `blazesym/` and `vmlinux.h/`. `host/build.sh`, `host/sockowner/build.sh` and `host/streaming/Makefile` build libbpf from it and take `vmlinux.h` from it; the Makefile also builds its bpftool. | BSD-3-Clause (`LICENSE`); libbpf LGPL-2.1 OR BSD-2-Clause; bpftool GPL-2.0-only OR BSD-2-Clause; see each folder |
| `dns-water-torture-detector/` | The DNS water-torture detector of another NETLAB project for the Tofino, unchanged. Its hairpin latency method (`../docs/p4_perf.md` section 4.1) is the one `switch/variants/hwl/` applies to this project's builds. `SOURCE_MANIFEST.json` lists its files' checksums. | not stated in the copy |

Change from upstream libbpf-bootstrap: this project's four monitors (`hostmon`, `execmon`, `modelmon`, `filemon`)
were in `examples/c/` until 2026-11-20. They moved to `host/streaming/`, and their names were removed from
`examples/c/Makefile`'s `APPS`.
