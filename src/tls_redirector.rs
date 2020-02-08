use native_tls::TlsAcceptor;
use openssl::ssl::{SslAcceptor, SslStream};
use std::borrow::BorrowMut;
use std::io::{Error, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

pub fn listen_tls(ext_addr: SocketAddr, ssl: SslAcceptor) -> Result<TcpListener, Error> {
    let loopback = Ipv4Addr::new(127, 0, 0, 1);
    let socket = SocketAddrV4::new(loopback, 0);
    let ret = TcpListener::bind(socket.clone())?;

    let ext_l = TcpListener::bind(ext_addr)?;
    let address_used = ret.local_addr()?;

    std::thread::spawn(move || {
        for conn_r in ext_l.incoming() {
            if conn_r.is_err() {
                continue;
            }
            let conn = conn_r.expect("Checked previously");
            let ssl_conn_r = ssl.accept(match conn.try_clone() {
                Ok(c) => c,
                Err(_) => {
                    continue;
                }
            });
            if ssl_conn_r.is_err() {
                println!(
                    "Ssl connection error. This could be an http client: {}",
                    ssl_conn_r.expect_err("")
                );
                continue;
            }
            let copy_to_r = TcpStream::connect(address_used);
            if copy_to_r.is_err() {
                println!("Server connection error: {}", copy_to_r.expect_err(""));
                continue;
            }
            keep_piping(
                copy_to_r.expect("Checked previously"),
                ssl_conn_r.expect("Checked previously"),
                conn,
            );
        }
    });

    return Ok(ret);
}

fn keep_piping(a: TcpStream, b: SslStream<TcpStream>, b_underlying: TcpStream) {
    if a.set_nonblocking(false).is_err() {
        return;
    };
    if b_underlying.set_nonblocking(false).is_err() {
        return;
    }
    if a.set_nodelay(false).is_err() {
        return;
    };
    if b_underlying.set_nodelay(false).is_err() {
        return;
    }

    let shared_ssl = Arc::new(Mutex::new(b));

    let ssl_for_a = shared_ssl.clone();
    let b_underlying_for_thread_a = match b_underlying.try_clone() {
        Ok(copy) => copy,
        Err(_) => return,
    };
    let mut a_for_a = match a.try_clone() {
        Err(_) => {
            return;
        }
        Ok(s) => s,
    };
    let mut a_for_b = match a.try_clone() {
        Err(_) => {
            return;
        }
        Ok(s) => s,
    };
    let shared_ssl_clone = shared_ssl.clone();

    // read from a coming from server, copy to b to client
    std::thread::spawn(move || {
        let mut buf = [0u8];
        loop {
            // println!("loop a");
            buf[0] = 0;
            match a_for_a.read(&mut buf) {
                Ok(count) => {
                    if count == 0 {
                        break; // was closed
                    }
                    match &mut shared_ssl.lock() {
                        Ok(stream) => {
                            match stream.deref_mut().borrow_mut().ssl_write(&buf) {
                                Err(e) => {
                                    stream.deref_mut().shutdown();
                                    break;
                                }
                                Ok(_) => {}
                            };
                        }
                        Err(e) => {
                            a.shutdown(std::net::Shutdown::Both);
                            b_underlying_for_thread_a.shutdown(std::net::Shutdown::Both);
                            break;
                        }
                    }
                }
                Err(e) => {
                    b_underlying_for_thread_a.shutdown(std::net::Shutdown::Both);
                    break;
                }
            }
        }
    });

    // read from b, copy to a
    std::thread::spawn(move || {
        let mut buf = [0u8; 1];
        let mut do_skip_peek = false; // ew. TODO refactor
        loop {
            buf[0] = 0;
            if !do_skip_peek && b_underlying.peek(&mut buf).is_err() {
                a_for_b.shutdown(std::net::Shutdown::Both);
                break;
            };
            match &mut shared_ssl_clone.lock() {
                Ok(stream) => {
                    match stream.deref_mut().ssl_read(&mut buf) {
                        Ok(count) => {
                            if count == 0 {
                                break;
                            }
                            match a_for_b.write(&buf) {
                                Err(e) => {
                                    b_underlying.shutdown(std::net::Shutdown::Both);
                                    println!("4 {}", e);
                                    break;
                                }
                                Ok(_) => {}
                            };
                            do_skip_peek = stream.ssl().pending() > 0;
                        }
                        Err(e) => {
                            a_for_b.shutdown(std::net::Shutdown::Both);
                            break;
                        }
                    };
                }
                Err(e) => {
                    a_for_b.shutdown(std::net::Shutdown::Both);
                    break;
                }
            }
        }
    });
}
