# Third-party components bundled here

CryptiQ Personal's WireGuard tunnel needs `wg`, `wg-quick`, a userspace
`wireguard-go` (macOS has no in-kernel WireGuard), and a bash 4+ interpreter
(`wg-quick` uses associative arrays; the `/bin/bash` macOS ships is 3.2).
Rather than require every user to install Homebrew and
`brew install wireguard-tools` themselves before the tunnel works at all,
these are bundled directly in the app.

| File | From | License |
|---|---|---|
| `wg`, `wg-quick` | [wireguard-tools](https://git.zx2c4.com/wireguard-tools/) | GPLv2 — see `COPYING-wireguard-tools` |
| `wireguard-go` | [wireguard-go](https://git.zx2c4.com/wireguard-go/) | MIT |
| `bash` | [GNU Bash](https://www.gnu.org/software/bash/) 5.3.15 | GPLv3+ — see `COPYING-bash` |
| `lib/libreadline.8.dylib`, `lib/libhistory.8.dylib` | [GNU Readline](https://www.gnu.org/software/readline/) | GPLv3+ |
| `lib/libncursesw.6.dylib` | [ncurses](https://invisible-island.net/ncurses/) | MIT-style |
| `lib/libintl.8.dylib` | [GNU gettext](https://www.gnu.org/software/gettext/) | LGPLv2.1+ |

These are unmodified upstream builds (via Homebrew), except: `bash`'s dynamic
library load paths were rewritten with `install_name_tool` from their
Homebrew Cellar locations to `@executable_path/lib/...` so it runs standalone
without Homebrew installed, and it was re-signed (ad-hoc) afterward since
that rewrite invalidates the existing signature. No source code was changed.
Source for every GPL/LGPL component here is available unmodified from the
upstream projects linked above; each also ships its full license text as a
`COPYING-*` file in this same directory.
