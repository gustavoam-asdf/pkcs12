// @ts-check
import { OPENSSL_V1_ENCRYPT_CONFIG, OPENSSL_V3_ENCRYPT_CONFIG, createPkcs12, Pkcs12Object, extractPkcs12 } from '../index.js'

import crypto from "node:crypto";
import fs from "node:fs/promises";
import test from 'ava'

const resourcesDir = `./__test__/resources`;
const resultsDir = `./__test__/results`;

await fs.mkdir(resultsDir, { recursive: true });


//TODO: Add tests for expected encrypt algorithms of created pfx reading it with openssl

test('build a pfx using openssl v3 encrypt config', async (t) => {
  const rootCA = await fs.readFile(`${resourcesDir}/root-ca.pem`, "utf8");
  const subCA = await fs.readFile(`${resourcesDir}/sub-ca.pem`, "utf8");
  const certificatePem = await fs.readFile(`${resourcesDir}/certificate.pem`, "utf8");
  const privateKeyPem = await fs.readFile(`${resourcesDir}/private-key.pem`, "utf8");

  t.notThrows(async () => {
    const pkcs = createPkcs12({
      alias: "test",
      certificatePem,
      privateKeyPem,
      password: "0123456789",
      caChainPem: [
        subCA,
        rootCA,
      ],
      encryptConfig: OPENSSL_V3_ENCRYPT_CONFIG
    })

    await fs.writeFile(`${resultsDir}/keystore-openssl-v3.pfx`, pkcs.base64, "base64");
  })
})

test('build a pfx using openssl v1 encrypt config', async (t) => {
  const rootCA = await fs.readFile(`${resourcesDir}/root-ca.pem`, "utf8");
  const subCA = await fs.readFile(`${resourcesDir}/sub-ca.pem`, "utf8");
  const certificatePem = await fs.readFile(`${resourcesDir}/certificate.pem`, "utf8");
  const privateKeyPem = await fs.readFile(`${resourcesDir}/private-key.pem`, "utf8");

  t.notThrows(async () => {
    const pkcs = createPkcs12({
      alias: "test",
      certificatePem,
      privateKeyPem,
      password: "0123456789",
      caChainPem: [
        subCA,
        rootCA,
      ],
      encryptConfig: OPENSSL_V1_ENCRYPT_CONFIG
    })

    await fs.writeFile(`${resultsDir}/keystore-openssl-v1.pfx`, pkcs.base64, "base64");
  })
})

test('throw invalid arg exception on create pkcs12', async (t) => {
  const randomString = (length) => {
    const randomBytes = crypto.getRandomValues(new Uint8Array(length));
    const base64String = btoa(String.fromCharCode(...randomBytes));

    return base64String;
  }

  const rootCA = await fs.readFile(`${resourcesDir}/root-ca.pem`, "utf8");
  const subCA = await fs.readFile(`${resourcesDir}/sub-ca.pem`, "utf8");
  const certificatePem = await fs.readFile(`${resourcesDir}/certificate.pem`, "utf8");
  const privateKeyPem = await fs.readFile(`${resourcesDir}/private-key.pem`, "utf8");

  t.throws(
    () => createPkcs12({
      certificatePem: randomString(100),
      privateKeyPem,
      password: "0123456789",
      caChainPem: [
        subCA,
        rootCA,
      ],
    }),
    {
      instanceOf: Error,
      code: 'InvalidArg',
      message: 'Failed to parse certificate'
    }
  )

  t.throws(
    () => createPkcs12({
      certificatePem,
      privateKeyPem: randomString(100),
      password: "0123456789",
      caChainPem: [
        subCA,
        rootCA,
      ],
    }),
    {
      instanceOf: Error,
      code: 'InvalidArg',
      message: 'Failed to parse private key'
    }
  )

  t.throws(
    () => createPkcs12({
      certificatePem,
      privateKeyPem,
      password: "0123456789",
      caChainPem: [
        randomString(100),
        rootCA,
      ],
    }),
    {
      instanceOf: Error,
      code: 'InvalidArg',
      message: 'Failed to parse caChainPem[0]'
    }
  )
})

test('extract all components from pfx created with openssl v1 encrypt config', async (t) => {
  const certificatePem = await fs.readFile(`${resourcesDir}/certificate.pem`, "utf8")
    .then(data => data.replace(/\r\n/g, '\n'));
  const privateKeyPem = await fs.readFile(`${resourcesDir}/private-key.pem`, "utf8")
    .then(data => data.replace(/\r\n/g, '\n'));
  const rootCA = await fs.readFile(`${resourcesDir}/root-ca.pem`, "utf8")
    .then(data => data.replace(/\r\n/g, '\n'));
  const subCA = await fs.readFile(`${resourcesDir}/sub-ca.pem`, "utf8")
    .then(data => data.replace(/\r\n/g, '\n'));

  const pfx = await fs.readFile(`${resourcesDir}/keystore-openssl-v1.pfx`, "base64");

  t.notThrows(() => {
    // Extract certificate
    const certificate = extractPkcs12({
      base64: pfx,
      password: "0123456789",
      object: Pkcs12Object.Certificate
    });
    t.is(certificate.object, Pkcs12Object.Certificate);
    t.is(certificate.pem, certificatePem);

    // Extract private key
    const privateKey = extractPkcs12({
      base64: pfx,
      password: "0123456789",
      object: Pkcs12Object.PrivateKey
    });
    t.is(privateKey.object, Pkcs12Object.PrivateKey);
    t.is(privateKey.pem, privateKeyPem);

    // Extract CA chain
    const caChain = extractPkcs12({
      base64: pfx,
      password: "0123456789",
      object: Pkcs12Object.CAChain
    });
    t.is(caChain.object, Pkcs12Object.CAChain);
    t.is(caChain.pem, `${subCA}${rootCA}`);
  })
})

test('extract all components from pfx created with openssl v3 encrypt config', async (t) => {
  const certificatePem = await fs.readFile(`${resourcesDir}/certificate.pem`, "utf8")
    .then(data => data.replace(/\r\n/g, '\n'));
  const privateKeyPem = await fs.readFile(`${resourcesDir}/private-key.pem`, "utf8")
    .then(data => data.replace(/\r\n/g, '\n'));
  const rootCA = await fs.readFile(`${resourcesDir}/root-ca.pem`, "utf8")
    .then(data => data.replace(/\r\n/g, '\n'));
  const subCA = await fs.readFile(`${resourcesDir}/sub-ca.pem`, "utf8")
    .then(data => data.replace(/\r\n/g, '\n'));

  const pfx = await fs.readFile(`${resourcesDir}/keystore-openssl-v3.pfx`, "base64");

  t.notThrows(() => {
    // Extract certificate
    const certificate = extractPkcs12({
      base64: pfx,
      password: "0123456789",
      object: Pkcs12Object.Certificate
    });
    t.is(certificate.object, Pkcs12Object.Certificate);
    t.is(certificate.pem, certificatePem);

    // Extract private key
    const privateKey = extractPkcs12({
      base64: pfx,
      password: "0123456789",
      object: Pkcs12Object.PrivateKey
    });
    t.is(privateKey.object, Pkcs12Object.PrivateKey);
    t.is(privateKey.pem, privateKeyPem);

    // Extract CA chain
    const caChain = extractPkcs12({
      base64: pfx,
      password: "0123456789",
      object: Pkcs12Object.CAChain
    });
    t.is(caChain.object, Pkcs12Object.CAChain);
    t.is(caChain.pem, `${subCA}${rootCA}`);
  })
})