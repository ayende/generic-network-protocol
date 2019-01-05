use memmem::{Searcher, TwoWaySearcher};
use std::collections::HashMap;
use tokio::codec::Decoder;

pub struct Cmd {
    pub args: Vec<String>,
    pub headers: HashMap<String, String>,
}

lazy_static! {
    static ref msg_break: TwoWaySearcher<'static> = { TwoWaySearcher::new(b"\r\n\r\n") };
}

pub struct CommandCodec {
    to_scan: usize,
}

impl CommandCodec {
    pub fn new() -> CommandCodec {
        CommandCodec { to_scan: 0 }
    }


    fn parse_cmd(cmd_str: &str) -> std::result::Result<Cmd, super::err::ConnectionError> {
        let mut lines = cmd_str.lines();

        let cmd_line = match lines.next() {
            None => {
                return Err(super::err::ConnectionError::parsing(cmd_str));
            }
            Some(v) => v,
        };

        let mut cmd = Cmd {
            args: cmd_line.split(' ').map(|s| s.to_string()).collect(),
            headers: HashMap::new(),
        };

        for line in lines {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(super::err::ConnectionError::parsing(line));
            }
            cmd.headers
                .insert(parts[0].trim().to_string(), parts[1].trim().to_string());
        }

        Ok(cmd)
    }
}

impl Decoder for CommandCodec {
    type Item = Cmd;
    type Error = super::err::ConnectionError;

    fn decode(
        &mut self,
        src: &mut bytes::BytesMut,
    ) -> std::result::Result<Option<Cmd>, super::err::ConnectionError> {
        if src.len() > 8192 {
            return Err(super::err::ConnectionError::MessageTooBig);
        }
        match msg_break.search_in(&src[self.to_scan..]) {
            None => {
                
                self.to_scan = src.len().checked_sub(3).unwrap_or(0);
                return Ok(None); // need to read more
            }
            Some(msg_end) => {
                let msg: String;
                {
                    msg =
                        String::from_utf8_lossy(&src[0..(self.to_scan + msg_end + 2)]).to_string();
                }
                src.advance(self.to_scan + msg_end + 4);
                self.to_scan = 0;
                let cmd = match CommandCodec::parse_cmd(&msg) {
                    Err(e) => return Err(e.into()),
                    Ok(r) => r,
                };
                return Ok(Some(cmd));
            }
        }
    }
}