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
use server::err::ConnectionError;
use std::sync::Arc;
use std::time::Duration;
use tokio::timer::Delay;
use futures::sync::mpsc::Sender;
use futures::prelude::await;
use futures::Sink;
use futures::prelude::*;
use std::time::Instant;

mod server;

fn echo(cmd: server::cmd::Cmd, sender : Sender<String>) -> std::result::Result<(), ConnectionError> {

    tokio::spawn(sender.send(cmd.args[1].clone()).map_err(|_|()).map(|_|()));

    Ok(())
}


fn remind(cmd: server::cmd::Cmd, sender : Sender<String>) -> std::result::Result<(), ConnectionError> {

    static COUNTER : std::sync::atomic::AtomicUsize = std::sync::atomic::ATOMIC_USIZE_INIT;
    // remdind <sec> msg

    #[async]
    fn delayed_send(delay: u64, msg: String, sender : Sender<String>) -> std::result::Result<(), ConnectionError> {

        await!(Delay::new(Instant::now() +Duration::from_secs(delay)))?;

        await!(sender.send(msg))?;

        Ok(())
    }


    let secs : u64  = match cmd.args.get(1){
        None => return Err(ConnectionError::BadDataArgs{
            msg: "'remind' requires a <secs> argument".to_string()
        }),
        Some(str) => match str.parse::<u64>(){
            Err(e) => return Err(ConnectionError::BadDataArgs{
                msg: "'remind' requires a <secs> argument to be a u64: ".to_string() + &e.to_string()
            }),
            Ok(v) => v
        }
    };
    let msg = match cmd.args.get(2){
        None => "Reminder",
        Some(v) => v
    };

    let id = (COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1).to_string();

    tokio::spawn(delayed_send(secs, msg.to_string() + "\r\nSequence: " + &id, sender.clone()).map_err(|_|()));

    tokio::spawn(sender.send("OK\r\nSequence: ".to_string() + &id).map_err(|_|()).map(|_|()));


    Ok(())

   

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
            .handle("echo", echo)
            .handle("remind", remind);
    }

    let listener = TcpListener::bind(&"127.0.0.1:4888".parse::<std::net::SocketAddr>()?)?;

    println!("Started");
    tokio::run(server::Server::accept_connections(server, listener).map_err(|_| ()));
    Ok(())
}