use argh::FromArgs;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Error},
    net::ToSocketAddrs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{split, AsyncBufReadExt, AsyncWriteExt, BufReader, WriteHalf},
    net::TcpListener,
    net::TcpStream,
    sync::mpsc::unbounded_channel,
    sync::{mpsc, Mutex},
};
use tokio_rustls::{
    rustls::{self, Certificate, PrivateKey},
    {server::TlsStream, TlsAcceptor},
};

use flexi_logger::{Duplicate, FileSpec, Logger, WriteMode};
#[macro_use]
extern crate log;

mod clients;
mod message;
use clients::{client_login_is_valid, Client};
use message::{create_message_text, parse_message, MessageErrorKind, MessageType};

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<MessageType>;

/// Shorthand for the receive half of the message channel.
type Rx = mpsc::UnboundedReceiver<MessageType>;

type SecuredSharedState = Arc<Mutex<SharedState>>;

struct SharedState {
    // User-Key -> Connection-ID -> Channel
    connections: HashMap<String, HashMap<String, Tx>>,
}

impl SharedState {
    fn new() -> SharedState {
        SharedState {
            connections: HashMap::new(),
        }
    }
}

const LOG_DIR: &str = "logs";
const AFK_TIMEOUT_SECS: u64 = 30;

#[derive(FromArgs, Debug)]
/// TLS-Server providing the backend for cute snoot boops
struct BoopOptions {
    ///client config file
    #[argh(positional)]
    clients_config: PathBuf,

    /// bind ip address with port
    #[argh(positional)]
    addr: String,

    /// show debug logging
    #[argh(switch, short = 'd')]
    debug: bool,

    /// tls cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// tls key file
    #[argh(option, short = 'k')]
    key: PathBuf,
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut std::io::BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    pkcs8_private_keys(&mut std::io::BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let options: BoopOptions = argh::from_env();

    tokio::fs::create_dir_all(LOG_DIR)
        .await
        .expect("failed to create logging directory");

    let level = if options.debug { "debug" } else { "info" };
    let duplicate_level = if options.debug {
        Duplicate::Debug
    } else {
        Duplicate::Info
    };

    Logger::try_with_str(level)
        .expect("failed to set logging configuration")
        .log_to_file(
            FileSpec::default()
                .directory(LOG_DIR)
                .basename("boop_server")
        )
        .write_mode(WriteMode::BufferAndFlush)
        .duplicate_to_stdout(duplicate_level)
        .start()
        .expect("failed to initialize logging");

    debug!("debug logging active");

    let clients = clients::read_clients_file(&options.clients_config)
        .await
        .expect("couldn't read clients config");
    info!("{} client entries read", clients.len());

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    let certs = load_certs(&options.cert)?;
    let mut keys = load_keys(&options.key)?;
    info!("{} TLS certs, {} TLS keys read", certs.len(), keys.len());

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&addr).await?;

    info!("started server on {}", options.addr);

    let state = Arc::new(Mutex::new(SharedState::new()));

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let clients_list = clients.clone();

        let state = Arc::clone(&state);

        tokio::spawn(async move {
            debug!("received connection attempt, trying tls handshake");

            if let Err(err) = handle_connection(&acceptor, stream, &clients_list, state).await {
                if err.kind() == io::ErrorKind::ConnectionReset {
                    warn!("client forcefully closed the connection");
                } else {
                    error!("connection error [{}]: {}", err.kind(), err);
                }
            }
        });
    }
}

async fn handle_connection(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    clients: &Vec<Client>,
    state: Arc<Mutex<SharedState>>,
) -> io::Result<()> {
    let stream = acceptor.accept(stream).await?;
    let (readhalf, mut writehalf) = split(stream);
    let mut reader = BufReader::new(readhalf);

    // check for connect call
    let mut cmd_buffer = String::new();
    let read_result = reader.read_line(&mut cmd_buffer).await;
    if let Err(err) = read_result {
        error!("there was an error reading from the connection: {}", &err);
        return Err(err);
    }

    // Initial Handshake

    let read = read_result.unwrap();
    if read == 0 {
        error!("EOF reached while reading from connection");
        return Err(Error::new(
            io::ErrorKind::UnexpectedEof,
            "EOF reached while reading from connection",
        ));
    }

    let parser_res = parse_message(&cmd_buffer);
    if let Err(err) = parser_res {
        return send_error_and_close(writehalf, err.into()).await;
    }

    let client_key;
    if let MessageType::CONNECT(key, password) = parser_res.unwrap() {
        // CORRECT CONNECT CALL

        let login_result = client_login_is_valid(&key, &password, clients);
        if login_result.is_err() || !login_result.unwrap() {
            // LOGIN WRONG
            info!("login failed, key: {}", &key);
            return send_message_and_close(writehalf, MessageType::NO).await;
        } else {
            // LOGIN CORRECT
            info!("logged in: {}", &key);
            send_message(&mut writehalf, MessageType::HEY).await?;
            client_key = key;
        }
    } else {
        // COMMAND SYNTAX IS CORRECT BUT ITS NOT A CONNECT CALL -> REFUSE
        return send_error_and_close(writehalf, MessageErrorKind::ProtocolMismatch).await;
    }

    // add client connection
    let connection_id = uuid::Uuid::new_v4().to_string();
    let (tx, mut rx): (Tx, Rx) = unbounded_channel();
    let mut watchdog = tokio::time::interval(Duration::from_secs(AFK_TIMEOUT_SECS));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay); // if tick is missed, fire next tick asap and then wait the full afk timeout again
    let mut was_pinged = true;

    // add connection to state
    add_connection(&client_key, &connection_id, tx, &state).await;

    loop {
        let mut buf = String::new();
        tokio::select! {
            _ = watchdog.tick() => {
                if !was_pinged {
                    debug!("connection {} timed out", {&connection_id});
                    writehalf.shutdown().await?;
                    remove_connection(&client_key, connection_id, &state).await;
                    return Ok(());
                }
                else {
                    was_pinged = false;
                }
            },
            res = reader.read_line(&mut buf) => match res {
                Ok(n) => {
                    if n == 0 { //EOF while reading
                        remove_connection(&client_key, connection_id, &state).await;
                        return Err(Error::from(io::ErrorKind::UnexpectedEof));
                    }

                    debug!("{}", &buf);
                    let parse_result = parse_message(&buf);
                    if let Ok(msg) = parse_result {
                        match msg {
                            MessageType::DISCONNECT => {
                                remove_connection(&client_key, connection_id, &state).await;
                                return send_message_and_close(writehalf, MessageType::BYE).await;
                            },
                            MessageType::PING => {
                                send_message(&mut writehalf, MessageType::PONG).await?;
                                was_pinged = true;
                            },
                            MessageType::BOOP(partner_key) => {
                                let state = state.lock().await;

                                if let Some(inner_map) = state.connections.get(&partner_key) {
                                    for (_, channel) in inner_map {
                                        let _ = channel.send(MessageType::BOOP(client_key.clone()));
                                    }
                                }
                            },
                            MessageType::AYT(partner_key) => {
                                let state = state.lock().await;

                                let msg = if state.connections.contains_key(&partner_key) {
                                    MessageType::ONLINE(partner_key)
                                }
                                else {
                                    MessageType::AFK(partner_key)
                                };

                                send_message(&mut writehalf, msg).await?;
                            },
                            _ => {
                                // against protocol -> disconnect
                                return send_error_and_close(writehalf, message::MessageErrorKind::ProtocolMismatch).await;
                            }
                        }
                    }
                    else { //close connection on non-compliant message
                        return send_error_and_close(writehalf, parse_result.unwrap_err().into()).await;
                    }
                },
                Err(err) => { //close connection on read error
                    error!("there was an error reading from the connection ({})... closing", &err);
                    remove_connection(&client_key, connection_id, &state).await;
                    return writehalf.shutdown().await;
                },
            },
            Some(msg) = rx.recv() => {
                send_message(&mut writehalf, msg).await?;
            }
        }
    }
}

async fn add_connection(
    client_key: &String,
    connection_id: &String,
    channel: Tx,
    state: &SecuredSharedState,
) {
    let mut state = state.lock().await;

    state
        .connections
        .entry(client_key.clone())
        .or_insert(HashMap::new())
        .insert(connection_id.clone(), channel);
}

async fn remove_connection(client_key: &String, connection_id: String, state: &SecuredSharedState) {
    let mut state = state.lock().await;

    state
        .connections
        .entry(client_key.clone())
        .and_modify(|inner_map| {
            inner_map.remove(&connection_id);
        });

    state.connections.retain(|_, inner_map| inner_map.len() > 0);
}

async fn send_error_and_close(
    writehalf: WriteHalf<TlsStream<TcpStream>>,
    err: message::MessageErrorKind,
) -> io::Result<()> {
    send_message_and_close(writehalf, MessageType::ERROR(err)).await
}

async fn send_message_and_close(
    mut writehalf: WriteHalf<TlsStream<TcpStream>>,
    message: message::MessageType,
) -> io::Result<()> {
    send_message(&mut writehalf, message).await?;
    writehalf.shutdown().await
}

async fn send_message(
    writehalf: &mut WriteHalf<TlsStream<TcpStream>>,
    message: message::MessageType,
) -> io::Result<()> {
    let msg_text = create_message_text(message);
    writehalf.write_all(msg_text.as_bytes()).await
}
