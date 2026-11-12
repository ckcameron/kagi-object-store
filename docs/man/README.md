<!-- SPDX-License-Identifier: CC-BY-NC-SA-4.0 -->

# Manual pages

Read a page from the checkout with `man -l docs/man/kagi-config.1`. Install the section 1 pages under the man directory on your system to read them by name.

```sh
sudo install -d /usr/local/share/man/man1
sudo install -m 0644 docs/man/*.1 /usr/local/share/man/man1/
man kagi-config
```

The [installer](kagi-install.1) also copies the pages to `$PREFIX/share/man/man1` when the source or package root contains `docs/man`. Install binaries separately. For a repository script, use the path in the page's synopsis.

- **Planner and nodes** [kagi-config](kagi-config.1), [kagi-cluster-host](kagi-cluster-host.1), [kagi-host](kagi-host.1), [kagi-install](kagi-install.1), [kagi-tls-cert](kagi-tls-cert.1), and [kagi-run](kagi-run.1).
- **Volumes** [kagi-volume-nbd](kagi-volume-nbd.1), [kagi-volume-attach](kagi-volume-attach.1), [kagi-volume-image](kagi-volume-image.1), [kagi-volume-qemu-scsi](kagi-volume-qemu-scsi.1), [kagi-volume-libvirt-scsi](kagi-volume-libvirt-scsi.1), [kagi-volume-iscsi-export](kagi-volume-iscsi-export.1), and [kagi-volume-hypervisor-notes](kagi-volume-hypervisor-notes.1).
- **Build and validation** [kagi-build](kagi-build.1), [kagi-bench](kagi-bench.1), [test-all](test-all.1), [coverage](coverage.1), and [kagi-security-check](kagi-security-check.1).
