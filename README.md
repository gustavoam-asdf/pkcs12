# PKCS #12

OpenSSL wrapper to handle PKCS #12 files.

## Roadmap

- [✓] Create a PKCS #12 file from a private key and a certificate.
- [✓] Create a PKCS #12 file from a private key and a certificate and a CA certificate.
- [✓] Support standard encryption algorithms of OpenSSL v1 and v3.
- [✗] Parse a PKCS #12 file and extract the private key and the certificate.
- [✗] Parse a PKCS #12 file and extract the private key, the certificate and the CA certificate.
- [✗] Parse and read a PKCS #12 information.

<!-- TODO: Verify that it is needed on production -->
## Install OpenSSL3 dependency

### Windows

```powershell
# Install vcpkg if you don't have it
git clone git@github.com:microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.bat
./vcpkg/vcpkg install openssl:x64-windows-release

# Set environment variables
$env:OPENSSL_DIR = "{{PATH_TO_VCPKG_DIR}}\installed\x64-windows-release"
$env:OPENSSL_MODULES = "{{PATH_TO_VCPKG_DIR}}\installed\x64-windows-release\bin"
```

### MacOS

```bash
brew install openssl@3
```

### Debian and Ubuntu

```bash
sudo apt-get install pkg-config libssl-dev
```

### Alpine

```bash
apk add pkgconf openssl-dev
```

## Quick usage

```javascript
import { createPkcs12 } from "@gaam/pkcs12";

const pkcs = createPkcs12({
	alias: "test",
	certificatePem,
	privateKeyPem,
	password: "0123456789",
	caChainPem: [
		subCA,
		rootCA,
	],
})
```