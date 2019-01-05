use custom_error::custom_error;

custom_error! {
    pub ConnectionError
    AddrParseError{source: std::net::AddrParseError} = "Unable to parse address {source}",
    Io{source: std::io::Error} = "unable to read from the network",
    Utf8{source: std::str::Utf8Error} = "Invalid UTF8 character sequence",
    Parse{origin: String} = "Unable to parse command: {origin}",
    MessageTooBig = "Message length was over 8KB",
    SslIssue{source : openssl::error::ErrorStack} = "OpenSSL error {source}",
    Handshake{source: openssl::ssl::HandshakeError<tokio::net::TcpStream>} = "Handshake error {source}",
    InvalidTimeFormat = "Unable to understand certificate time",
    ClientCertExpired{date: String} = "The client certificate has already expired: {date}",
    ClientCertNotYetValid{date: String} = "The client certificate is not yet valid: {date}",
    UnfamiliarCertiicateCert = "The client certificate is not known to the server",
    InvalidCertiicateCert = "Failed to authenticate a client certificate (invalid)",
    InvalidCommand{cmd: String} = "Invalid command {cmd}"
}

impl ConnectionError {
    pub fn parsing(origin: &str) -> ConnectionError {
        ConnectionError::Parse {
            origin: origin.to_string(),
        }
    }
}
