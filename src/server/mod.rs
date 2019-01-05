pub mod err;
pub mod cmd;

use futures::prelude::*;
use foreign_types_shared::ForeignTypeRef;
use futures::prelude::await;
use std::collections::{HashSet, HashMap};
use std::io;
use std::sync::Arc;
use tokio::codec::FramedRead;
use tokio::io::write_all;
use tokio::net::tcp::TcpStream;
use tokio::net::TcpListener;
use tokio_io::{AsyncRead};
use tokio_openssl::SslAcceptorExt;

use self::err::ConnectionError;
use self::cmd::CommandCodec;

type Handler = fn(self::cmd::Cmd) -> Result<String, ConnectionError>;

pub struct Server {
    tls: openssl::ssl::SslAcceptor,
    allowed_certs_thumbprints: HashSet<String>,
    cmd_handlers: HashMap<String, Handler> 
}

impl Server {
    pub fn new(
        cert_path: &str,
        key_path: &str,
        allowed_certs_thumbprints: &[&str],
    ) -> std::result::Result<Arc<Server>, ConnectionError> {
        let mut allowed = HashSet::new();

        for thumbprint in allowed_certs_thumbprints {
            allowed.insert(thumbprint.to_lowercase());
        }

        let mut sslb = openssl::ssl::SslAcceptor::mozilla_modern(openssl::ssl::SslMethod::tls())?;
        sslb.set_private_key_file(key_path, openssl::ssl::SslFiletype::PEM)?;
        sslb.set_certificate_chain_file(cert_path)?;
        sslb.check_private_key()?;
        // accept all certificates, we'll do our own validation on them
        sslb.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |_, _| true);

        let server = Server {
            tls: sslb.build(),
            allowed_certs_thumbprints: allowed,
            cmd_handlers: HashMap::new()
        };
        Ok(Arc::new(server))
    }

    pub fn handle(&mut self, name: String, handler: Handler) {
        self.cmd_handlers.insert(name, handler);
    }

    #[async]
    pub fn accept_connections(
        server : Arc<Server>,
        listener: TcpListener,
    ) -> std::result::Result<(), io::Error> {
        #[async]
        for connection in listener.incoming() {
            // `connection` here has type `TcpStream`
            tokio::spawn(Server::handle_connection(server.clone(), connection).map_err(|_| ()));
        }
        Ok(())
    }

    #[async]
    fn handle_connection(
        server: Arc<Server>,
        connection: TcpStream,
    ) -> std::result::Result<(), ConnectionError> {
        let acceptor = server.tls.clone();
        let stream = await!(acceptor.accept_async(connection))?;

        let auth_result = match Server::authenticate_certificate(server.clone(), stream.get_ref().ssl()) {
            // failed to auth
            Ok(Some((msg, err))) => Some((msg, err)),
            // failed to figure it out
            Err(e) => Some((e.to_string(), ConnectionError::InvalidCertiicateCert)),
            // successfully auth
            Ok(None) => None,
        };

        let (reader, mut writer) = stream.split();

        if let Some((msg, e)) = auth_result {
            await!(write_all(writer, msg.into_bytes()))?;
            return Err(e);
        }

        writer = await!(write_all(writer, "OK\r\n".to_string()))?.0;
        
        let cmds = FramedRead::new(reader, CommandCodec::new());

        #[async]
        for cmd in cmds {
            let cmd_to_run = server.cmd_handlers.get(&cmd.args[0])
                .map(|h| h.clone());
            match cmd_to_run {
                None => {
                    await!(write_all(writer, format!("ERR Uknown command {}", cmd.args[0])))?;
                    return Err(ConnectionError::InvalidCommand{cmd: cmd.args[0].clone()});
                },
                Some(f) =>{
                    match f(cmd){
                        Err(e) => {
                             await!(write_all(writer, e.to_string()))?;
                             return Err(e);
                        },
                        Ok(v) => {
                             writer = await!(write_all(writer, v))?.0;
                             writer = await!(write_all(writer, b"\r\n\r\n"))?.0;
                        }
                    }
                }
            }
        }

        Ok(())
    }


    fn authenticate_certificate(
        server : Arc<Server>, 
        ssl: &openssl::ssl::SslRef
    ) -> std::result::Result<Option<(String, ConnectionError)>, ConnectionError> {
        fn get_friendly_name(peer: &openssl::x509::X509) -> String {
            peer.subject_name() // can't figure out how to get the real friendly name
                .entries()
                .last()
                .map(|it| {
                    it.data()
                        .as_utf8()
                        .and_then(|s| Ok(s.to_string()))
                        .unwrap_or("".to_string())
                })
                .unwrap_or("<Unknown>".to_string())
        }

        extern "C" {
            fn ASN1_TIME_diff(
                pday: *mut std::os::raw::c_int,
                psec: *mut std::os::raw::c_int,
                from: *const openssl_sys::ASN1_TIME,
                to: *const openssl_sys::ASN1_TIME,
            ) -> std::os::raw::c_int;
        }

        fn is_before(
            x: &openssl::asn1::Asn1TimeRef,
            y: &openssl::asn1::Asn1TimeRef,
        ) -> std::result::Result<bool, ConnectionError> {
            unsafe {
                let mut day: std::os::raw::c_int = 0;
                let mut sec: std::os::raw::c_int = 0;
                match ASN1_TIME_diff(&mut day, &mut sec, x.as_ptr(), y.as_ptr()) {
                    0 => Err(ConnectionError::InvalidTimeFormat),
                    _ => Ok(day > 0 || sec > 0),
                }
            }
        }

        fn is_valid_time(peer: &openssl::x509::X509) -> std::result::Result<(), ConnectionError> {
            let now = openssl::asn1::Asn1Time::days_from_now(0)?;

            if is_before(&now, peer.not_before())? {
                return Err(ConnectionError::ClientCertNotYetValid {
                    date: peer.not_before().to_string(),
                });
            }
            if is_before(peer.not_after(), &now)? {
                return Err(ConnectionError::ClientCertExpired {
                    date: peer.not_after().to_string(),
                });
            }

            Ok(())
        }

        match ssl.peer_certificate() {
            None => {
                return Ok(Some((
                    "ERR No certificate was provided\r\n".to_string(),
                    ConnectionError::InvalidCertiicateCert,
                )));
            }
            Some(peer) => {
                let thumbprint = hex::encode(peer.digest(openssl::hash::MessageDigest::sha1())?);
                if server.allowed_certs_thumbprints.contains(&thumbprint) == false {
                    let msg = format!(
                        "ERR certificate ({}) thumbprint '{}' is unknown\r\n",
                        get_friendly_name(&peer),
                        thumbprint
                    );
                    return Ok(Some((msg, ConnectionError::UnfamiliarCertiicateCert)));
                }

                if let Err(e) = is_valid_time(&peer) {
                    let msg = format!(
                        "ERR certificate ({}) thumbprint '{}' cannot be used: {}\r\n",
                        get_friendly_name(&peer),
                        thumbprint,
                        e
                    );
                    return Ok(Some((msg, e)));
                }
            }
        };
        return Ok(None);
    }
}
