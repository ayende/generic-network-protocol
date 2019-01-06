#![feature(generators)]
#![feature(proc_macro_hygiene)]

extern crate bytes;
extern crate custom_error;
extern crate foreign_types_shared;
extern crate hex;
extern crate memmem;
extern crate openssl;
extern crate openssl_sys;
extern crate tokio;
extern crate tokio_openssl;

extern crate futures_await as futures;
extern crate tokio_io;

#[macro_use]
extern crate lazy_static;
use tokio::net::TcpListener;
use futures::prelude::*;
use server::err::ConnectionError;
use std::sync::Arc;

mod server;

fn echo(cmd: server::cmd::Cmd) -> std::result::Result<String, ConnectionError> {

    Ok(cmd.args[1].clone())

}

fn main() -> std::result::Result<(), server::err::ConnectionError> {
    let mut server = server::Server::new(
        "C:\\Work\\temp\\example-com.cert.pem",
        "C:\\Work\\temp\\example-com.key.pem",
        // allowed thumprints
        &["1776821db1002b0e2a9b4ee3d5ee14133d367009"],
    )?;

    {
        Arc::get_mut(&mut server).unwrap()
            .handle("echo".to_string(), echo);
    }

    let listener = TcpListener::bind(&"127.0.0.1:4888".parse::<std::net::SocketAddr>()?)?;

    println!("Started");
    tokio::run(server::Server::accept_connections(server, listener).map_err(|_| ()));
    Ok(())
}