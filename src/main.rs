use anyhow::{Context, Result};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{
        extension::{ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier},
        X509Extension, X509NameBuilder, X509Req,
    },
};

static COUNTRY: &str = "AU";
static STATE: &str = "Some-State";
static CITY: &str = "Springfield";
static ORGANIZATION: &str = "Example";
static EMAIL_ADDRESS: &str = "help@example.com";

/// Generate private key
fn generate_private_key(key_size: u32) -> Result<PKey<Private>> {
    let rsa = Rsa::generate(key_size)?;

    Ok(PKey::from_rsa(rsa)?)
}

/// Generate Certificate Request (CSR) from a key
fn generate_csr_from_key(key_pair: &PKeyRef<Private>, identity: String) -> Result<Vec<u8>> {
    // Create a new X509NameBuilder
    let mut name_builder = X509NameBuilder::new()?;
    name_builder
        .append_entry_by_text("C", COUNTRY)
        .context("couldn't set the Country")?;
    name_builder
        .append_entry_by_text("ST", STATE)
        .context("couldn't set the State")?;
    name_builder
        .append_entry_by_text("L", CITY)
        .context("couldn't set the City")?;
    name_builder
        .append_entry_by_text("O", ORGANIZATION)
        .context("couldn't set the Organization")?;
    name_builder
        .append_entry_by_text("CN", identity.as_str())
        .context("couldn't set the Identity (common name)")?;
    name_builder
        .append_entry_by_text("emailAddress", EMAIL_ADDRESS)
        .context("couldn't set the Email address")?;

    // Build the X509Name object
    let name = name_builder.build();

    // Generate certificate signing request (CSR)
    let mut req_builder = X509Req::builder()?;
    req_builder.set_version(0x2)?;
    req_builder.set_subject_name(name.as_ref())?;
    req_builder.set_pubkey(key_pair)?;
    req_builder.sign(key_pair, MessageDigest::sha256())?;

    let mut extensions = Stack::new()?;
    extensions.push(X509Extension::new(None, None, "nsCertType", "server")?)?;
    extensions.push(SubjectKeyIdentifier::new().build(&req_builder.x509v3_context(None))?)?;
    extensions.push(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    extensions.push(ExtendedKeyUsage::new().server_auth().build()?)?;
    extensions.push(
        SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .dns("localhost")
            .build(&req_builder.x509v3_context(None))?,
    )?;

    req_builder.add_extensions(extensions.as_ref())?;

    Ok(req_builder.build().to_pem()?)
}

fn main() {
    let key = generate_private_key(4096).unwrap();

    println!(
        "Key:\n{}",
        std::str::from_utf8(key.private_key_to_pem_pkcs8().unwrap().as_slice()).unwrap()
    );

    let csr = generate_csr_from_key(key.as_ref(), "localhost".into()).unwrap();

    println!("CSR:\n{}", std::str::from_utf8(csr.as_slice()).unwrap());
}
