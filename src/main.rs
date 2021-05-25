#[cfg(feature = "cli")]
use std::fmt::{Display, Write};
#[cfg(feature = "cli")]
use std::sync::Arc;

#[cfg(feature = "cli")]
use structopt::StructOpt;

#[cfg(feature = "cli")]
use kmip_client::ConnectionDetails;
#[cfg(feature = "cli")]
use kmip_client::{Key, KeyType, get_server_info, op_to_string};

#[cfg(feature = "cli")]
struct Pkcs11ToolLikeKey(Key);

#[cfg(feature = "cli")]
impl Display for Pkcs11ToolLikeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0.key_type {
            kmip_client::KeyType::PUBLIC => f.write_str("Public"),
            kmip_client::KeyType::PRIVATE => f.write_str("Private"),
            kmip_client::KeyType::UNKNOWN => f.write_str("Unknown"),
        }?;
        f.write_str(" Key Object: ")?;
        match (&self.0.algorithm, &self.0.length) {
            (kmip_client::AlgorithmType::RSA, Some(len)) => {
                f.write_fmt(format_args!("RSA {} bits", len))?;
            },
            _ => {}
        };
        f.write_char('\n')?;
        if let Some(name) = &self.0.name {
            f.write_fmt(format_args!("  label:      {}\n", name))?;
        }
        f.write_fmt(format_args!("  ID:         {}\n", &self.0.id))
    }
}

#[cfg(feature = "cli")]
#[derive(Debug, StructOpt)]
#[structopt(name = "kmip-tool", about = "A tool for querying a KMIP server")]
struct Opt {
    /// Activate info mode
    #[structopt(short = "I", long = "show-info")]
    info_mode: bool,

    /// Activate object list mode
    #[structopt(short = "O", long = "list-objects")]
    object_list_mode: bool,

    /// Activate sign mode
    #[structopt(short = "s", long = "sign")]
    sign_mode: bool,

    /// Delete object mode
    #[structopt(short = "b", long = "delete-object")]
    delete_mode: bool,

    /// Revoke object mode
    #[structopt(short = "r", long = "revoke-object")]
    revoke_mode: bool,

    /// Create key
    #[structopt(short = "c", long = "create-key")]
    create_key_mode: bool,

    /// ID of the object related to the requested action
    #[structopt(short = "d", long = "id")]
    id: Option<String>,

    #[structopt(short = "u", long = "username")]
    username: Option<String>,

    #[structopt(short = "p", long = "password")]
    password: Option<String>,

    #[structopt(long = "ca-cert-path")]
    server_ca_cert_path: Option<String>,

    #[structopt(long = "client-cert-path")]
    client_cert_path: Option<String>,

    #[structopt(long = "client-key-path")]
    client_cert_private_key_path: Option<String>,

    #[structopt(long = "insecure")]
    insecure: bool,

    #[structopt(long = "host", default_value = "localhost")]
    host: String,

    #[structopt(long = "port", default_value = "5696")]
    port: u16,

    /// Silence all output
    #[structopt(short = "q", long = "quiet")]
    quiet: bool,

    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: usize,

    /// Timestamp (sec, ms, ns, none)
    #[structopt(short = "t", long = "timestamp")]
    ts: Option<stderrlog::Timestamp>,   
}

#[cfg(not(feature = "cli"))]
fn main() {

}

#[cfg(feature = "cli")]
fn main() {
    let opt = Opt::from_args();

    stderrlog::new()
        .module(module_path!())
        .quiet(opt.quiet)
        .verbosity(opt.verbose)
        .timestamp(opt.ts.unwrap_or(stderrlog::Timestamp::Off))
        .init()
        .unwrap();

    let mut conn = ConnectionDetails::new(opt.host, opt.port);

    if opt.insecure {
        conn.set_insecure();
    } else if let Some(path) = &opt.server_ca_cert_path {
        conn.set_server_ca_cert(path);
    }

    // TODO: Do we need to check that we have BOTH cert and key?
    if let Some(path) = &opt.client_cert_path {
        conn.set_client_cert(path);
    }
    if let Some(path) = &opt.client_cert_private_key_path {
        conn.set_client_cert_private_key(path);
    }

    match (&opt.username, &opt.password) {
        (None, None) => { },
        (None, Some(_)) => panic!("Password specified but username missing"),
        (Some(_), None) => panic!("Username specified but password missing"),
        (Some(u), Some(p)) => { conn.set_credentials(u.clone(), p.clone()) },
    };

    let conn = Arc::new(conn);

    if opt.info_mode {
        let si = get_server_info(conn.clone()).unwrap();
        println!("KMIP server information:");
        si.id.iter().for_each(|txt| println!("  {}", txt));
        println!("Supported KMIP versions:");
        println!("  {}", si.supported_versions.join(", "));
        println!("Supported KMIP operations:");
        println!("  {}", si.supported_ops.iter().map(|s| op_to_string(s)).collect::<Vec<&str>>().join(", "));
    } else if opt.object_list_mode {
        let pub_key_ids = kmip_client::locate(conn.clone(), None, Some(KeyType::PUBLIC)).unwrap();
        let priv_key_ids = kmip_client::locate(conn.clone(), None, Some(KeyType::PRIVATE)).unwrap();
        for key_id in pub_key_ids.iter().chain(priv_key_ids.iter()) {
            if let Ok(key) = kmip_client::get_key(conn.clone(), key_id) {
                println!("{}", Pkcs11ToolLikeKey(key));
            }
        }
    } else if opt.sign_mode {
        kmip_client::sign(conn.clone(), opt.id.as_ref().unwrap(), b"hello").unwrap();
    } else if opt.revoke_mode {
        kmip_client::revoke_key(conn.clone(), opt.id.as_ref().unwrap()).unwrap();
    } else if opt.delete_mode {
        kmip_client::destroy_key(conn.clone(), opt.id.as_ref().unwrap()).unwrap();
    }
}