# PKCS #12

OpenSSL wrapper to handle PKCS #12 files.

## Roadmap

- [✓] **PKCS #12 Creation**: Generate PKCS #12 files from private keys and certificates with certificate authority chains
- [✓] **Encryption Support**: Full compatibility with standard OpenSSL v1 and v3 encryption algorithms
- [✓] **PKCS #12 Parsing**: Extract and decode private keys, certificates, and CA chains from existing PKCS #12 files
- [✗] **Information Reading**: Parse and display detailed PKCS #12 metadata and structure information

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

### Creating a PKCS #12 file

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

### Extracting objects from a PKCS #12 file

```javascript
import { extractPkcs12, Pkcs12Object } from "@gaam/pkcs12";

// Extract certificate
const certificate = extractPkcs12({
	base64: pkcs12Base64,
	password: "0123456789",
	object: Pkcs12Object.Certificate
});

// Extract private key
const privateKey = extractPkcs12({
	base64: pkcs12Base64,
	password: "0123456789",
	object: Pkcs12Object.PrivateKey
});

// Extract CA chain
const caChain = extractPkcs12({
	base64: pkcs12Base64,
	password: "0123456789",
	object: Pkcs12Object.CAChain
});
```