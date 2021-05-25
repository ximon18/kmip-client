use std::{error::Error, fmt::Display, io::{Read, Write}, net::TcpStream, path::PathBuf, sync::Arc};
use std::str;

use kmip::{ATTR_NAME_NAME, CryptographicAlgorithm, ObjectType, Tag, kmip_ttlv::{parse_ttlv_len, Ttlv}};
use log::{Level::{Debug,  Trace}, warn};
use log::{debug, log_enabled, trace};
use openssl::ssl::{SslFiletype, SslVerifyMode};
use openssl::ssl::{SslConnector, SslMethod};

pub use kmip::Operation;

pub const KMIP_MAX_BUFFER_LEN: usize = 2048;

#[derive(Clone, Debug)]
pub struct UsernamePassword{ username: String, password: String }

#[derive(Clone, Debug)]
pub struct ConnectionDetails {
    credentials: Option<UsernamePassword>,
    hostname: String,
    port: u16,
    server_ca_cert_path: Option<PathBuf>, // only used if insecure is false
    client_cert_path: Option<PathBuf>,
    client_cert_private_key_path: Option<PathBuf>,
    insecure: bool,
}

impl Display for ConnectionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", &self.hostname, &self.port))
    }
}

impl ConnectionDetails {
    pub fn new<H>(hostname: H, port: u16) -> Self
        where H: Into<String>
    {
        ConnectionDetails {
            credentials: None,
            hostname: hostname.into(),
            port,
            server_ca_cert_path: None,
            client_cert_path: None,
            client_cert_private_key_path: None,
            insecure: false,
        }
    }

    pub fn set_server_ca_cert<P: Into<PathBuf>>(&mut self, ca_cert_path: P) {
        self.server_ca_cert_path = Some(ca_cert_path.into());
    }

    pub fn set_client_cert<P: Into<PathBuf>>(&mut self, cert_path: P) {
        self.client_cert_path = Some(cert_path.into());
    }

    pub fn set_client_cert_private_key<P: Into<PathBuf>>(&mut self, key_path: P) {
        self.client_cert_private_key_path = Some(key_path.into());
    }

    pub fn set_credentials<S: Into<String>>(&mut self, username: S, password: S) {
        self.credentials = Some(UsernamePassword{
            username: username.into(),
            password: password.into()
        });
    }

    pub fn set_insecure(&mut self) {
        warn!("Disabling KMIP TLS server certificate verification.");
        self.insecure = true;
    }

    pub fn visa_creds<'a>(&'a self) -> Option<(&'a str, &'a str)> {
        match &self.credentials {
            Some(up) => Some((&up.username, &up.password)),
            None => None
        }
    }
}

#[derive(Debug)]
pub enum KeyType {
    PUBLIC,
    PRIVATE,
    UNKNOWN,
}

#[derive(Debug)]
pub enum AlgorithmType {
    RSA,
    UNKNOWN,
}

#[derive(Debug)]
pub struct Key {
    pub id: String,
    pub name: Option<String>,
    pub key_type: KeyType,
    pub algorithm: AlgorithmType,
    pub length: Option<i32>,
}

pub struct ServerInfo {
    pub id: Vec<String>,
    pub supported_versions: Vec<String>,
    pub supported_ops: Vec<Operation>,
}

pub fn op_to_string(op: &Operation) -> &'static str {
    match op {
        Operation::Create => "Create",
        Operation::CreateKeyPair => "CreateKeyPair",
        Operation::Register => "Register",
        Operation::ReKey => "ReKey",
        Operation::DeriveKey => "DeriveKey",
        Operation::Certify => "Certify",
        Operation::Recertify => "Recertify",
        Operation::Locate => "Locate",
        Operation::Check => "Check",
        Operation::Get => "Get",
        Operation::GetAttributes => "GetAttributes",
        Operation::GetAttributesList => "GetAttributesList",
        Operation::AddAttribute => "AddAttribute",
        Operation::ModifyAttribute => "ModifyAttribute",
        Operation::DeleteAttribute => "DeleteAttribute",
        Operation::ObtainLease => "ObtainLease",
        Operation::GetUsageAllocation => "GetUsageAllocation",
        Operation::Activate => "Activate",
        Operation::Revoke => "Revoke",
        Operation::Destroy => "Destroy",
        Operation::Archive => "Archive",
        Operation::Recover => "Recover",
        Operation::Validate => "Validate",
        Operation::Query => "Query",
        Operation::Cancel => "Cancel",
        Operation::Poll => "Poll",
        Operation::Notify => "Notify",
        Operation::Put => "Put",
        Operation::RekeyKeyPair => "RekeyKeyPair",
        Operation::DiscoverVersions => "DiscoverVersions",
        Operation::Encrypt => "Encrypt",
        Operation::Decrypt => "Decrypt",
        Operation::Sign => "Sign",
        Operation::SignatureVerify => "SignatureVerify",
        Operation::Mac => "Mac",
        Operation::MacVerify => "MacVerify",
        Operation::RngRetrieve => "RngRetrieve",
        Operation::RngSeed => "RngSeed",
        Operation::Hash => "Hash",
        Operation::CreateSplitKey => "CreateSplitKey",
        Operation::JoinSplitKey => "JoinSplitKey",
        Operation::Import => "Import",
        Operation::Export => "Export",
        Operation::Log => "Log",
        Operation::Login => "Login",
        Operation::Logout => "Logout",
        Operation::DelegatedLogin => "DelegatedLogin",
        Operation::AdjustAttribute => "AdjustAttribute",
        Operation::SetAttribute => "SetAttribute",
        Operation::SetEndpointRole => "SetEndpointRole",
    }
}

#[derive(Debug)]
pub enum KmipError {
    NotFound,
    Custom(String),
}

impl Error for KmipError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}

impl Display for KmipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmipError::Custom(msg) => f.write_fmt(format_args!("KmipError: {}", msg)),
            KmipError::NotFound => f.write_str("KmipError: Not Found"),
        }
    }
}

fn create_tls_connection(conn: Arc<ConnectionDetails>) -> openssl::ssl::SslStream<TcpStream> {
    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();

    if conn.insecure {
        connector.set_verify(SslVerifyMode::NONE);
    } else {
        if let Some(path) = &conn.server_ca_cert_path {
            connector.set_ca_file(path).unwrap();
        }
    }

    if let Some(path) = &conn.client_cert_path {
        connector.set_certificate_file(path, SslFiletype::PEM).unwrap();
    }
    if let Some(path) = &conn.client_cert_private_key_path {
        connector.set_private_key_file(path, SslFiletype::PEM).unwrap();
    }

    let connector = connector.build();

    let host_with_port = format!("{}:{}", conn.hostname, conn.port);

    trace!("Open TCP connection to {}", host_with_port);
    let stream = TcpStream::connect(&host_with_port).unwrap();

    trace!("Initiate TLS session");
    connector.connect(&conn.hostname, stream).unwrap()
}

pub fn make_kmip_request<'a, 'b, 'c>(
    conn: Arc<ConnectionDetails>,
    op: (Operation, Ttlv<'b>),
    buf: &'c mut [u8; KMIP_MAX_BUFFER_LEN],
) -> Ttlv<'c> {
    if log_enabled!(Trace) {
        trace!("Performing KMIP operation: {:?}", op);
    } else if log_enabled!(Debug) {
        debug!("Performing KMIP operation: {:?}", op.0);
    }

    // Encode locate request to buffer
    let request_len = kmip::request(conn.visa_creds(), op).encode(buf).unwrap();
    let mut tls = create_tls_connection(conn);

    // Send/recieve over tls stream
    tls.write(&buf[..request_len]).unwrap();
    tls.read(&mut buf[..8]).unwrap();
    let response_len = parse_ttlv_len(&buf[4..8]) + 8;
    tls.read(&mut buf[8..response_len]).unwrap();

    // Decode query response from buffer
    let (ttlv_response, parsed_len) = Ttlv::decode(&buf[..response_len]).unwrap();
    assert_eq!(response_len, parsed_len);

    ttlv_response
}

pub fn get_server_info<'a>(
    conn: Arc<ConnectionDetails>,
) -> Result<ServerInfo, KmipError> {
    let mut supported_versions = Vec::new();
    let mut id = Vec::new();
    let mut supported_ops = Vec::new();

    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];

    // Try DiscoverVersions first, but it was only introduced in KMIP 1.1, it wasn't part of KMIP 1.0
    let response = make_kmip_request(conn.clone(), kmip::discover_versions(), buf);
    if let Ok(payload) = kmip::collect_response_payload(&response) {
        for child in payload.child_iter().unwrap() {
            let tag: Tag = child.tag();
            match tag {
                Tag::ProtocolVersion => {
                    let ver_major = child.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::ProtocolVersionMajor));
                    let ver_minor = child.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::ProtocolVersionMinor));
                    match (ver_major, ver_minor) {
                        (Some(maj), Some(min)) => {
                            let int_maj: i32 = maj.value().unwrap();
                            let int_min: i32 = min.value().unwrap();
                            supported_versions.push(format!("{}.{}", int_maj, int_min));
                        }
                        _ => {}
                    };
                }
                Tag::Operation => {
                    let op_code: u32 = child.value().unwrap();
                    let op: Option<Operation> = num::FromPrimitive::from_u32(op_code);
                    if let Some(op) = op {
                        supported_ops.push(op);
                    }
                }
                _ => {}
            }
        }
    } else {
        // Assume this is a KMIP 1.0 only server
        supported_versions.push("1.0".to_string());
    }

    // Query doesn't require credentials
    // Quoting the KMIP Usage Guide 1.0 section 3.2 Authorization for Revoke, Recover, Destroy and Archive Operations:
    //   "This authentication is performed for all KMIP operations, with the single exception of the Query operation."
    // See: http://docs.oasis-open.org/kmip/ug/v1.0/cs01/kmip-ug-1.0-cs-01.html#_Toc262558163
    let response = make_kmip_request(conn.clone(), kmip::query(), buf);
    let payload = kmip::collect_response_payload(&response).unwrap();

    for child in payload.child_iter().unwrap() {
        let tag: Tag = child.tag();
        match tag {
            Tag::VendorIdentification => {
                let txt: &str = child.value().unwrap();
                id.push(txt.to_owned());
            }
            Tag::Operation => {
                let op_code: u32 = child.value().unwrap();
                let op: Option<Operation> = num::FromPrimitive::from_u32(op_code);
                if let Some(op) = op {
                    supported_ops.push(op);
                }
            }
            _ => {}
        }
    }

    Ok(ServerInfo {
        id, supported_versions, supported_ops,
    })
}

pub fn create_rsa_key_pair<'a>(
    conn: Arc<ConnectionDetails>,
    pub_key_name: &str,
    priv_key_name: &str,
    num_modulus_bits: u16,
) -> Result<(String, String), KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let response = make_kmip_request(conn.clone(), kmip::create_rsa_key_pair(pub_key_name, priv_key_name, num_modulus_bits), buf);
    let payload = kmip::collect_response_payload(&response).unwrap();
    let priv_key_id: &str = payload.path(&[Tag::PrivateKeyUniqueIdentifier])
        .map_err(|err| KmipError::Custom(format!("Missing private key id for key: {:?}", err)))?
        .value()
        .map_err(|err| KmipError::Custom(format!("Unable to extract id for for private key: {:?}", err)))?;
    let pub_key_id: &str = payload.path(&[Tag::PublicKeyUniqueIdentifier])
        .map_err(|err| KmipError::Custom(format!("Missing public key id for key: {:?}", err)))?
        .value()
        .map_err(|err| KmipError::Custom(format!("Unable to extract id for for public key: {:?}", err)))?;
    Ok((priv_key_id.to_owned(), pub_key_id.to_owned()))
}

pub fn activate_key<'a>(
    conn: Arc<ConnectionDetails>,
    key_id: &str,
) -> Result<(), KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let response = make_kmip_request(conn.clone(), kmip::activate_key(key_id), buf);
    kmip::collect_response_payload(&response)
        .map_err(|err| KmipError::Custom(format!("Failed to activate key: {:?}", err)))?;
    Ok(())
}

pub fn revoke_key<'a>(
    conn: Arc<ConnectionDetails>,
    key_id: &str,
) -> Result<(), KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let response = make_kmip_request(conn.clone(), kmip::revoke_key(key_id), buf);
    kmip::collect_response_payload(&response)
        .map_err(|err| KmipError::Custom(format!("Failed to revoke key: {:?}", err)))?;
    Ok(())
}

pub fn locate<'a>(
    conn: Arc<ConnectionDetails>,
    key_name: Option<&str>,
    key_type: Option<KeyType>,
) -> Result<Vec<String>, KmipError> {
    let object_type = match key_type {
        Some(KeyType::PUBLIC) => Some(ObjectType::PublicKey),
        Some(KeyType::PRIVATE) => Some(ObjectType::PrivateKey),
        Some(_other) => return Err(KmipError::Custom("Unsupported key type".to_owned())),
        None => None,
    };

    let mut results: Vec<String> = Vec::new();
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let response = make_kmip_request(conn.clone(), kmip::locate(key_name, object_type), buf);
    let payload = kmip::collect_response_payload(&response).unwrap();
    results.extend(payload
        .child_iter()
        .unwrap()
        .filter(|item| matches!(item.tag(), Tag::UniqueIdentifier))
        .map(|item| item.value::<&str>().unwrap().to_owned()));

    Ok(results)
}

pub fn set_key_name<'a>(
    conn: Arc<ConnectionDetails>,
    pub_id: &str,
    key_name: &str,
) -> Result<(), KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let response = make_kmip_request(conn.clone(), kmip::set_name(pub_id, key_name), buf);
    kmip::collect_response_payload(&response)
        .map_err(|err| KmipError::Custom(format!("Failed to set key name: {:?}", err)))?;
    Ok(())
}

pub fn get_key_name<'a>(
    conn: Arc<ConnectionDetails>,
    key_id: &str,
) -> Result<String, KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let response = make_kmip_request(conn.clone(), kmip::get_attr(key_id, ATTR_NAME_NAME), buf);
    let payload = kmip::collect_response_payload(&response).unwrap();
    Ok(payload.path(&[Tag::Attribute, Tag::AttributeValue, Tag::NameValue])
        .map_err(|_| KmipError::NotFound)?
        .value::<&str>()
        .map_err(|err| KmipError::Custom(format!("Unable to extract name for key: {:?}", err)))?
        .to_owned())
}

pub enum RsaPublicKey {
    DerEncoded(Vec<u8>),
    Components{modulus: Vec<u8>, public_exponent: Vec<u8>},
}

pub fn get_rsa_key_material<'a>(
    conn: Arc<ConnectionDetails>,
    pub_id: &str
) -> Result<RsaPublicKey, KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let response = make_kmip_request(conn.clone(), kmip::get(pub_id), buf);
    let payload = kmip::collect_response_payload(&response).unwrap();
    let key_material = payload.path(&[Tag::PublicKey, Tag::KeyBlock, Tag::KeyValue, Tag::KeyMaterial]).
        map_err(|err| KmipError::Custom(format!("Unable to locate material for key: {:?}", err)))?;

    // key material can be in one of two forms:
    //   - tag: 0x43 (Key Material)
    //     value: ByteString (DER encoded ASN.1 of the form:
    //       SEQUENCE (2 elem)
    //         INTEGER (2048 bit) 249730518378804514563022639424194188122844634854387503862562335150551… - i.e. modulus
    //         INTEGER 65537                                                                             - i.e. exponent
    //
    // OR
    //
    //  - tag: 0x43 (Key Material)
    //    value: Structure
    //      tag: 0x52 (Modulus)
    //      value: BigInteger
    //      tag: 0x6C (Public Exponent)
    //      value: BigInteger
    //
    // There doesn't appear to be a way from the KMIP specification to tell which of the two is returned. The spec does
    // show that a key format type parameter can be passed in the get request, but it's unclear if that guarantees that
    // you will get the requested format back or if the request can fail because the requesed format is unavailable or
    // unsupported. I believe these two types are known as "Raw" and "Transparent RSA Public Key" and are just two of
    // many possible key format types.
    //
    // See: Key Management Interoperability Protocol Specification Version 1.0:
    //   - Section 2.1.3 "Key Block":
    //       http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_Toc262581157
    //   - Section 2.1.7.5 "Transparent RSA Public Key":
    //       http://docs.oasis-open.org/kmip/spec/v1.0/os/kmip-spec-1.0-os.html#_toc1012
    //
    // So, first we try and interpret the response data as "Raw" bytes, and if that fails try instead to interpret it as
    // a "Transparent RSA Public Key" structure.

    if let Ok(bytes) = key_material.value::<&[u8]>() {
        Ok(RsaPublicKey::DerEncoded(bytes.to_vec()))
    } else {
        let modulus: &[u8] = key_material.path(&[Tag::Modulus])
            .map_err(|err| KmipError::Custom(format!("Unable to locate modulus for key: {:?}", err)))?
            .value()
            .map_err(|err| KmipError::Custom(format!("Unable to extract modulus bytes for key: {:?}", err)))?;
        let public_exponent: &[u8] = key_material.path(&[Tag::PublicExponent])
            .map_err(|err| KmipError::Custom(format!("Unable to locate public exponent for key: {:?}", err)))?
            .value()
            .map_err(|err| KmipError::Custom(format!("Unable to extract public exponent bytes for key: {:?}", err)))?;
        Ok(RsaPublicKey::Components{
            modulus: modulus.to_vec(),
            public_exponent: public_exponent.to_vec(),
        })
    }
}

pub fn get_key<'a>(
    conn: Arc<ConnectionDetails>,
    key_id: &str
) -> Result<Key, KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let response = make_kmip_request(conn.clone(), kmip::get(key_id), buf);
    let payload = kmip::collect_response_payload(&response)
        .map_err(|err| KmipError::Custom(format!("Failed to get key: {:?}", err)))?;

    let id = payload.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::UniqueIdentifier)).unwrap();
    let id = id.value::<&str>().unwrap().to_owned();

    let object_type = payload.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::ObjectType)).unwrap();
    use num::FromPrimitive;
    let key_type = match ObjectType::from_u32(object_type.value().unwrap()) {
        Some(ObjectType::PublicKey) => KeyType::PUBLIC,
        Some(ObjectType::PrivateKey) => KeyType::PRIVATE,
        _ => KeyType::UNKNOWN,
    };

    let mut algorithm = AlgorithmType::UNKNOWN;
    let mut length = None;

    match key_type {
        KeyType::PUBLIC | KeyType::PRIVATE => {
            let key_item = match key_type {
                KeyType::PUBLIC => {
                    payload.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::PublicKey))
                }
                KeyType::PRIVATE => {
                    payload.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::PrivateKey))
                }
                _ => None
            }.unwrap();

            let key_block_item = key_item.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::KeyBlock)).unwrap();
            let crypto_alg_item = key_block_item.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::CryptographicAlgorithm)).unwrap();
            let crypto_alg_type = CryptographicAlgorithm::from_u32(crypto_alg_item.value().unwrap());
            if let Some(CryptographicAlgorithm::Rsa) = crypto_alg_type {
                algorithm = AlgorithmType::RSA;
            }
            let crypto_len_item = key_block_item.child_iter().unwrap().find(|item| matches!(item.tag(), Tag::CryptographicLength)).unwrap();
            length = Some(crypto_len_item.value().unwrap());
        }
        _ => {}
    }

    let name = get_key_name(conn, &id).ok();

    let key = Key { id, name, key_type, algorithm, length };

    Ok(key)
}

pub fn sign<'a>(
    conn: Arc<ConnectionDetails>,
    key_id: &str,
    data: &[u8],
) -> Result<Vec<u8>, KmipError> {
    // TODO: should the response buffer size be related to the size of the data to be signed?
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let req = kmip::sign(key_id, data);
    let response = make_kmip_request(conn.clone(), req, buf);
    let payload = kmip::collect_response_payload(&response)
        .map_err(|err| KmipError::Custom(format!("Failed to sign data: {:?}", err)))?;
    let signature_bytes: &[u8] = payload.path(&[Tag::SignatureData])
        .map_err(|err| KmipError::Custom(format!("Unable to locate signature in signed response: {:?}", err)))?
        .value()
        .map_err(|err| KmipError::Custom(format!("Unable to extract signature bytes from signed response: {:?}", err)))?;
    Ok(signature_bytes.to_vec())
}

pub fn destroy_key<'a>(
    conn: Arc<ConnectionDetails>,
    key_id: &str,
) -> Result<(), KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let req = kmip::destroy_key(key_id);
    let response = make_kmip_request(conn.clone(), req, buf);
    kmip::collect_response_payload(&response)
        .map_err(|err| KmipError::Custom(format!("Failed to destroy key: {:?}", err)))?;
    Ok(())
}

pub fn generate_random<'a>(
    conn: Arc<ConnectionDetails>,
    data_length: i32,
) -> Result<Vec<u8>, KmipError> {
    // TODO: should the response buffer size be related to the size of the data to be generated?
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let req = kmip::rng_retrieve(data_length);
    let response = make_kmip_request(conn.clone(), req, buf);
    let payload = kmip::collect_response_payload(&response)
        .map_err(|err| KmipError::Custom(format!("Failed to generate random data: {:?}", err)))?;
    let random_bytes: &[u8] = payload.path(&[Tag::Data])
        .map_err(|err| KmipError::Custom(format!("Unable to locate random data in response: {:?}", err)))?
        .value()
        .map_err(|err| KmipError::Custom(format!("Unable to extract random bytes from response: {:?}", err)))?;
    Ok(random_bytes.to_vec())
}

pub fn register_key<'a>(
    conn: Arc<ConnectionDetails>,
    key_id: &str,
) -> Result<(), KmipError> {
    let buf = &mut [0u8; KMIP_MAX_BUFFER_LEN];
    let req = kmip::destroy_key(key_id);
    let response = make_kmip_request(conn.clone(), req, buf);
    kmip::collect_response_payload(&response)
        .map_err(|err| KmipError::Custom(format!("Failed to destroy key: {:?}", err)))?;
    Ok(())
}