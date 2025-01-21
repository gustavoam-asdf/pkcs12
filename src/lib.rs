#![deny(clippy::all)]

use openssl::{base64, pkcs12::Pkcs12, pkey::PKey, stack::Stack, x509::X509};

#[macro_use]
extern crate napi_derive;

#[napi(object)]
pub struct CreatePkcs12Args {
  pub password: String,
  pub private_key_pem: String,
  pub certificate_pem: String,
  pub full_chain_pem: Vec<String>,
}

#[napi]
pub fn create_pkcs12(args: CreatePkcs12Args) -> String {
  let certificates = args.full_chain_pem.iter().map(|pem_cert| {
    let cert_der = X509::from_pem(pem_cert.as_bytes()).expect("Failed to parse certificate");
    cert_der
  });

  let mut full_chain: Stack<X509> = Stack::new().expect("Failed to create stack");

  for cert in certificates {
    full_chain.push(cert).expect("Failed to push certificate");
  }

  let certificate =
    X509::from_pem(args.certificate_pem.as_bytes()).expect("Failed to parse certificate");

  let private_key_bytes = base64::decode_block(&args.private_key_pem).unwrap();
  let private_key =
    PKey::private_key_from_pem(private_key_bytes.as_slice()).expect("Failed to parse private key");

  let mut pfx_builder = Pkcs12::builder();

  pfx_builder.cert(&certificate);
  pfx_builder.pkey(&private_key);
  pfx_builder.ca(full_chain);

  let builded_pfx = pfx_builder
    .build2(&args.password)
    .expect("Failed to build pfx");

  let pfx_bytes = builded_pfx.to_der().expect("Failed to convert pfx to der");

  let pfx_base64 = base64::encode_block(&pfx_bytes);

  pfx_base64
}
