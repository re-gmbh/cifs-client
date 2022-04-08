# A minimal, Rust-native CIFS client library

This project was born from the need at [RE:](https://www.r-ecosystem.de/) to connect to SMBv1 shares.

As such, the implementation herein is not planned to become a fully-fledged SMB & CIFS implementation but driven by our very specific needs. Nonetheless we're open to contributions and hope that this library might help others with similar needs.

## Features

- connect to SMBv1 servers
- authenticate via NTLM using domain, username & password
- download files

## Contributing

If you find that there's some feature not covered by this implementation, or you happen to find a bug, we'll welcome pull requests with your improvements.

In case you want to get in touch and discuss some specific aspects, feel free to use the [discussions feature at Github](https://github.com/re-gmbh/cifs/discussions/).
