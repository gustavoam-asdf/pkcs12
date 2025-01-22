import { createPkcs12 } from '../index.js'
import fs from "node:fs/promises";
import test from 'ava'

test('build a pfx', async (t) => {
  const rootCA = await fs.readFile(`./__test__/resources/root-ca.pem`, "utf8");
  const subCA = await fs.readFile(`./__test__/resources/sub-ca.pem`, "utf8");
  const certificatePem = await fs.readFile(`./__test__/resources/certificate.pem`, "utf8");
  const privateKeyPem = await fs.readFile(`./__test__/resources/private-key.pem`, "utf8");

  t.notThrows(() => {
    createPkcs12({
      certificatePem,
      privateKeyPem,
      password: "password",
      fullChainPem: [
        certificatePem,
        subCA,
        rootCA,
      ],
    })
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
      password: "password",
      fullChainPem: [
        certificatePem,
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
      password: "password",
      fullChainPem: [
        certificatePem,
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
      password: "password",
      fullChainPem: [
        randomString(100),
        subCA,
        rootCA,
      ],
    }),
    {
      instanceOf: Error,
      code: 'InvalidArg',
      message: 'Failed to parse full_chain_pem[0]'
    }
  )
})