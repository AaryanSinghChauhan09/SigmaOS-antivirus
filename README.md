# SigmaOS antivirus

This crate is currently a `no_std` identity scaffold. Its library constructs a
`Component` named `SigmaOS-antivirus`; it does not scan files, identify
malware, or enforce a security policy. The inline unit test checks only the
fixed name. Do not rely on it as an antivirus control.

## Build

```sh
cargo check --lib
```

## License

Apache-2.0. See [`Cargo.toml`](Cargo.toml).

