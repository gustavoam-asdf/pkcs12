#![deny(clippy::all)]

use napi::Error;
use openssl::{
  base64, hash::MessageDigest, nid::Nid, pkcs12::Pkcs12, pkey::PKey, provider::Provider,
  stack::Stack, x509::X509,
};

#[macro_use]
extern crate napi_derive;

#[napi(string_enum)]
pub enum EncryptAlgorithm {
  PBEWithSHA1And3KeyTripleDesCBC,
  PBEWithSHA1And2KeyTripleDesCBC,
  PBEWithSHA1And128BitRC2CBC,
  PBEWithSHA1And40BitRC2CBC,
  AES256CBC,
}

impl EncryptAlgorithm {
  pub fn to_nid(&self) -> Nid {
    match self {
      Self::PBEWithSHA1And3KeyTripleDesCBC => Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC,
      Self::PBEWithSHA1And2KeyTripleDesCBC => Nid::PBE_WITHSHA1AND2_KEY_TRIPLEDES_CBC,
      Self::PBEWithSHA1And128BitRC2CBC => Nid::PBE_WITHSHA1AND128BITRC2_CBC,
      Self::PBEWithSHA1And40BitRC2CBC => Nid::PBE_WITHSHA1AND40BITRC2_CBC,
      Self::AES256CBC => Nid::AES_256_CBC,
    }
  }
}

#[napi(string_enum)]
pub enum MacMessageDigest {
  SHA1,
  SHA256,
  SHA384,
  SHA512,
}

impl MacMessageDigest {
  pub fn to_message_digest(&self) -> MessageDigest {
    match self {
      Self::SHA1 => MessageDigest::sha1(),
      Self::SHA256 => MessageDigest::sha256(),
      Self::SHA384 => MessageDigest::sha384(),
      Self::SHA512 => MessageDigest::sha512(),
    }
  }
}

#[napi(object)]
pub struct EncryptConfig {
  pub certificate_algorithm: EncryptAlgorithm,
  pub private_key_algorithm: EncryptAlgorithm,
  pub mac_algorithm: MacMessageDigest,
}

#[napi]
pub const OPENSSL_V1_ENCRYPT_CONFIG: EncryptConfig = EncryptConfig {
  certificate_algorithm: EncryptAlgorithm::PBEWithSHA1And40BitRC2CBC,
  private_key_algorithm: EncryptAlgorithm::PBEWithSHA1And3KeyTripleDesCBC,
  mac_algorithm: MacMessageDigest::SHA1,
};

#[napi]
pub const OPENSSL_V3_ENCRYPT_CONFIG: EncryptConfig = EncryptConfig {
  certificate_algorithm: EncryptAlgorithm::AES256CBC,
  private_key_algorithm: EncryptAlgorithm::AES256CBC,
  mac_algorithm: MacMessageDigest::SHA256,
};

#[napi(object)]
pub struct CreatePkcs12Args {
  pub alias: Option<String>,
  pub password: String,
  pub private_key_pem: String,
  pub certificate_pem: String,
  pub ca_chain_pem: Vec<String>,
  pub encrypt_config: Option<EncryptConfig>,
}

#[napi(object)]
pub struct CreatedPkcs12 {
  pub base64: String,
}

#[napi]
pub fn create_pkcs12(args: CreatePkcs12Args) -> Result<CreatedPkcs12, Error> {
  openssl::init();
  let loaded_provider_result = Provider::try_load(None, "legacy", true);

  if let Err(e) = loaded_provider_result {
    return Err(Error::new(
      napi::Status::GenericFailure,
      format!(
        "Failed to activate legacy openssl v1 mode with error: {:#?}",
        e
      ),
    ));
  }

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

  let created_ca_stack = Stack::<X509>::new();

  if let Err(_) = created_ca_stack {
    return Err(Error::new(
      napi::Status::GenericFailure,
      "Failed to create full chain",
    ));
  }

  let mut ca_stack = created_ca_stack.unwrap();

  for (i, ca_pem) in args.ca_chain_pem.iter().enumerate() {
    let ca_parsed = X509::from_pem(ca_pem.as_bytes());

    if let Err(_) = ca_parsed {
      return Err(Error::new(
        napi::Status::InvalidArg,
        format!("Failed to parse caChainPem[{}]", i),
      ));
    }

    let ca_added = ca_stack.push(ca_parsed.unwrap());

    if let Err(_) = ca_added {
      return Err(Error::new(
        napi::Status::GenericFailure,
        format!("Failed to add caChainPem[{}] to full chain", i),
      ));
    }
  }

  // Openssl v1
  // pfx_builder.cert_algorithm(Nid::PBE_WITHSHA1AND40BITRC2_CBC);
  // pfx_builder.key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC);
  // pfx_builder.mac_md(MessageDigest::sha1());

  // Openssl v3
  // pfx_builder.cert_algorithm(Nid::AES_256_CBC);
  // pfx_builder.key_algorithm(Nid::AES_256_CBC);
  // pfx_builder.mac_md(MessageDigest::sha256());

  let encrypt_config: EncryptConfig = args
    .encrypt_config
    .unwrap_or_else(|| OPENSSL_V3_ENCRYPT_CONFIG);

  let mut pfx_builder = Pkcs12::builder();

  pfx_builder.cert_algorithm(encrypt_config.certificate_algorithm.to_nid());
  pfx_builder.key_algorithm(encrypt_config.private_key_algorithm.to_nid());
  pfx_builder.mac_md(encrypt_config.mac_algorithm.to_message_digest());

  if let Some(alias) = args.alias {
    pfx_builder.name(&alias);
  }

  pfx_builder.cert(&certificate_parsed.unwrap());
  pfx_builder.pkey(&private_key_parsed.unwrap());
  pfx_builder.ca(ca_stack);

  let builded_pfx_result = pfx_builder.build2(&args.password);

  if let Err(e) = builded_pfx_result {
    println!("Build error: {:#?}", e);
    return Err(Error::new(
      napi::Status::GenericFailure,
      "Failed to build pfx",
    ));
  }

  let builded_pfx = builded_pfx_result.unwrap();

  let pfx_bytes = builded_pfx.to_der().expect("Failed to convert pfx to der");

  let pfx_base64 = base64::encode_block(&pfx_bytes);

  Ok(CreatedPkcs12 { base64: pfx_base64 })
}
