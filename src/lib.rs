#![deny(clippy::all)]

use napi::Error;
use openssl::{base64, nid::Nid, pkcs12::Pkcs12, pkey::PKey, stack::Stack, x509::X509};

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
pub fn create_pkcs12(args: CreatePkcs12Args) -> Result<String, Error> {
  let certificate_parsed = X509::from_pem(args.certificate_pem.as_bytes());

  if let Err(_) = certificate_parsed {
    return Err(Error::new(
      napi::Status::InvalidArg,
      "Failed to parse certificate",
    ));
  }

  let private_key_parsed = PKey::private_key_from_pem(args.private_key_pem.as_bytes());

  if let Err(_) = private_key_parsed {
    return Err(Error::new(
      napi::Status::InvalidArg,
      "Failed to parse private key",
    ));
  }

  let created_full_chain = Stack::<X509>::new();

  if let Err(_) = created_full_chain {
    return Err(Error::new(
      napi::Status::GenericFailure,
      "Failed to create full chain",
    ));
  }

  let mut full_chain = created_full_chain.unwrap();

  for (i, pem_cert) in args.full_chain_pem.iter().enumerate() {
    let certificate_parsed = X509::from_pem(pem_cert.as_bytes());

    if let Err(_) = certificate_parsed {
      return Err(Error::new(
        napi::Status::InvalidArg,
        format!("Failed to parse full_chain_pem[{}]", i),
      ));
    }

    let certificate_added = full_chain.push(certificate_parsed.unwrap());

    if let Err(_) = certificate_added {
      return Err(Error::new(
        napi::Status::GenericFailure,
        format!("Failed to add full_chain_pem[{}] to full chain", i),
      ));
    }
  }

  let mut pfx_builder = Pkcs12::builder();

  pfx_builder.key_algorithm(Nid::PBE_WITHSHA1AND2_KEY_TRIPLEDES_CBC);
  pfx_builder.cert_algorithm(Nid::PBE_WITHSHA1AND2_KEY_TRIPLEDES_CBC);

  pfx_builder.cert(&certificate_parsed.unwrap());
  pfx_builder.pkey(&private_key_parsed.unwrap());
  pfx_builder.ca(full_chain);

  let builded_pfx_result = pfx_builder.build2(&args.password);

  if let Err(e) = builded_pfx_result {
    println!("{:#?}", e);
    return Err(Error::new(
      napi::Status::GenericFailure,
      "Failed to build pfx",
    ));
  }

  let builded_pfx = builded_pfx_result.unwrap();

  let pfx_bytes = builded_pfx.to_der().expect("Failed to convert pfx to der");

  let pfx_base64 = base64::encode_block(&pfx_bytes);

  Ok(pfx_base64)
}
