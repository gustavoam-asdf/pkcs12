import { OPENSSL_V1_ENCRYPT_CONFIG, OPENSSL_V3_ENCRYPT_CONFIG, createPkcs12 } from '../index.js'

import crypto from "node:crypto";
import fs from "node:fs/promises";
import test from 'ava'

//TODO: Add tests for expected encrypt algorithms of created pfx reading it with openssl

test('build a pfx using openssl v3 encrypt config', async (t) => {
  const rootCA = await fs.readFile(`./__test__/resources/root-ca.pem`, "utf8");
  const subCA = await fs.readFile(`./__test__/resources/sub-ca.pem`, "utf8");
  const certificatePem = await fs.readFile(`./__test__/resources/certificate.pem`, "utf8");
  const privateKeyPem = await fs.readFile(`./__test__/resources/private-key.pem`, "utf8");

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

    await fs.writeFile(`./__test__/resources/keystore-openssl-v3.pfx`, pkcs.base64, "base64");
  })
})

test('build a pfx using openssl v1 encrypt config', async (t) => {
  const rootCA = await fs.readFile(`./__test__/resources/root-ca.pem`, "utf8");
  const subCA = await fs.readFile(`./__test__/resources/sub-ca.pem`, "utf8");
  const certificatePem = await fs.readFile(`./__test__/resources/certificate.pem`, "utf8");
  const privateKeyPem = await fs.readFile(`./__test__/resources/private-key.pem`, "utf8");

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

    await fs.writeFile(`./__test__/resources/keystore-openssl-v1.pfx`, pkcs.base64, "base64");
  })
})

test('throw invalid arg exception', async (t) => {
  const randomString = (length) => {
    const randomBytes = crypto.getRandomValues(new Uint8Array(length));
    const base64String = btoa(String.fromCharCode(...randomBytes));

    return base64String;
  }

  const rootCA = await fs.readFile(`./__test__/resources/root-ca.pem`, "utf8");
  const subCA = await fs.readFile(`./__test__/resources/sub-ca.pem`, "utf8");
  const certificatePem = await fs.readFile(`./__test__/resources/certificate.pem`, "utf8");
  const privateKeyPem = await fs.readFile(`./__test__/resources/private-key.pem`, "utf8");

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