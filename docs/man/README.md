<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Manual pages

Install all section-1 pages locally with:

```sh
sudo install -d /usr/local/share/man/man1
sudo install -m 0644 docs/man/*.1 /usr/local/share/man/man1/
mandb 2>/dev/null || true
```

The `kagi-install` helper performs the copy automatically when run from a source/package tree containing `docs/man`.
