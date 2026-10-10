# Third-party notices

The root [MIT license](LICENSE) applies to project-owned ida-agent code and
documentation. Third-party files retain their original copyright notices and
licenses; the root license does not replace them.

## IDA SDK

`ida-sdk/` is a pinned submodule of the public
[Hex-Rays SDK](https://github.com/HexRaysSA/ida-sdk). Its own MIT license is
available at `ida-sdk/LICENSE` after `git submodule update --init ida-sdk`.
The SDK submodule is synchronized as a Git link, without copying its history or
files into this repository. Running IDA and Hex-Rays requires their own licenses.

## Qt 6.8.2 Windows headers and configuration

`qt-sdk/qt-6.8.2-win/` contains Qt headers and build configuration, with the
original notices and SPDX license expressions retained. The applicable license
texts are in [LICENSES](qt-sdk/qt-6.8.2-win/LICENSES), copied from
[Qt Base v6.8.2](https://github.com/qt/qtbase/tree/v6.8.2/LICENSES).
Most headers offer LGPL-3.0-only or the GPL alternatives listed in each file;
some files use GPL with the Qt exception, Unicode, AFL or Boost licenses.
Consult each file's expression rather than applying the project's MIT license.
The original file notices also cover bundled third-party code such as Catch.
No Qt runtime libraries, private IDA Qt link bundles, IDA executables or licenses
are published by source synchronization. Plugin binaries use IDA's bundled Qt.

## IDAPython skill

`skills/idapython/` includes material adapted from `mrexodia/ida-pro-mcp`.
Its attribution and MIT license are preserved in
[NOTICE.md](skills/idapython/NOTICE.md) and [LICENSE](skills/idapython/LICENSE).

## Build-time dependencies

Go modules are pinned in `ida-mcp/go.mod` and `ida-mcp/go.sum`. CMake scripts
select dependencies such as SQLite and curl for platform builds. These
upstreams retain their own licenses; fetching or linking them does not change
their terms. See the relevant dependency and packaging scripts before
redistributing a modified build.
