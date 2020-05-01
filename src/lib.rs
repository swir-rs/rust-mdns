#[macro_use]
extern crate log;

extern crate byteorder;
extern crate dns_parser;
extern crate futures;
extern crate get_if_addrs;
extern crate libc;
extern crate multimap;
extern crate net2;
extern crate nix;
extern crate rand;

use dns_parser::Name;

use crate::futures::StreamExt;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time;

mod address_family;
mod fsm;
#[cfg(windows)]
#[path = "netwin.rs"]
mod net;
#[cfg(not(windows))]
mod net;
mod record;
mod services;

use address_family::{Inet, Inet6};
use fsm::{Command, FSM};
use services::{ResolveListener, ServiceData, Services, ServicesInner};

const DEFAULT_TTL: u32 = 60;
const MDNS_PORT: u16 = 5353;

#[allow(non_snake_case)]
enum State {
    Active,
    Stopped,
}

pub struct Responder {
    fsms: Vec<FSM>,
    advertised_services: Services,
    resolved_services: Services,
    commands: Arc<RwLock<CommandSender>>,
    state: Arc<RwLock<State>>,
}

pub struct Service {
    pub id: String,
}

impl Responder {
    pub fn new() -> io::Result<Responder> {
        let mut hostname = net::gethostname()?;
        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        let advertised_services = Arc::new(RwLock::new(ServicesInner::new(hostname.clone())));
        let resolved_services = Arc::new(RwLock::new(ServicesInner::new(hostname)));

        let v4 = FSM::new(&advertised_services, &resolved_services, Inet());
        let v6 = FSM::new(&advertised_services, &resolved_services, Inet6());
        let mut fsms = vec![];

        let commands = match (v4, v6) {
            (Ok((v4_fsm, v4_command)), Ok((v6_fsm, v6_command))) => {
                fsms.push(v4_fsm);
                fsms.push(v6_fsm);
                vec![v4_command, v6_command]
            }

            (Ok((v4_fsm, v4_command)), Err(_)) => {
                fsms.push(v4_fsm);
                vec![v4_command]
            }

            (Err(err), _) => return Err(err),
        };

        let commands = CommandSender(commands);
        let responder = Responder {
            fsms,
            advertised_services,
            resolved_services,
            commands: Arc::new(RwLock::new(commands)),
            state: Arc::new(RwLock::new(State::Active)),
        };

        Ok(responder)
    }

    #[allow(non_snake_case)]
    pub fn start(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut tasks = vec![];
        for fsm in self.fsms.iter() {
            let (r, w) = fsm.start();
            tasks.push(r);
            tasks.push(w);
        }

        let services = self.resolved_services.clone();
        let commands = self.commands.clone();
        let state = self.state.clone();

        let handle = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(5));
            while let Some(instant) = interval.next().await {
                debug!("Resolve periodically at {:?}", instant);
                let guard = state.read().await;
                if let State::Stopped = &*guard {
                    info!("Notifications stopped");
                    return;
                }

                let services = services.write().await;
                for svc in services.get_all().iter() {
                    let commands = commands.clone();
                    let svc = svc.clone();
                    commands.write().await.send_resolve_request(svc).await;
                }
            }
        });
        tasks.push(handle);
        tasks
    }

    pub async fn shutdown(&self) {
        let mut state = self.state.write().await;
        *state = State::Stopped;
        self.commands.write().await.send_shutdown().await;
    }
}

impl Responder {
    fn check_txt(&self, txt: &[&str]) -> Vec<u8> {
        if txt.is_empty() {
            vec![0]
        } else {
            txt.iter()
                .flat_map(|entry| {
                    let entry = entry.as_bytes();
                    if entry.len() > 255 {
                        panic!("{:?} is too long for a TXT record", entry);
                    }
                    std::iter::once(entry.len() as u8).chain(entry.iter().cloned())
                })
                .collect()
        }
    }

    pub async fn register(
        &self,
        svc_type: String,
        svc_name: String,
        port: u16,
        txt: &[&str],
    ) -> Result<Service, ()> {
        info!("Register");
        let txt = self.check_txt(txt);

        let svc = ServiceData {
            svc_type: Name::from_str(format!("{}", svc_type)).unwrap(),
            svc_name: Name::from_str(format!("{}.{}", svc_name, svc_type)).unwrap(),
            port,
            txt,
        };

        self.commands
            .write()
            .await
            .send_unsolicited(svc.clone(), DEFAULT_TTL, true)
            .await;

        self.advertised_services
            .write()
            .await
            .register(svc)
            .map(|s| Service { id: s })
            .map_err(|_| ())
    }

    pub async fn advertise_gratitously(
        &self,
        svc_type: String,
        svc_name: String,
        port: u16,
        txt: &[&str],
    ) {
        info!("Advertise gratitously");
        let txt = self.check_txt(txt);

        let svc = ServiceData {
            svc_type: Name::from_str(format!("{}", svc_type)).unwrap(),
            svc_name: Name::from_str(format!("{}.{}", svc_name, svc_type)).unwrap(),
            port,
            txt,
        };
        self.commands
            .write()
            .await
            .send_unsolicited(svc.clone(), DEFAULT_TTL, true)
            .await;
    }

    pub async fn resolve(&self, svc_type: String, listener: ResolveListener) {
        info!("Resolve {}", svc_type);

        let svc = ServiceData {
            svc_type: Name::from_str(format!("{}", svc_type)).unwrap(),
            svc_name: Name::from_str(format!("{}", svc_type)).unwrap(),
            port: 0,
            txt: vec![],
        };

        let mut services = self.resolved_services.write().await;
        let rr = services.register(svc.clone());

        match rr {
            Ok(id) => {
                services.add_listener(id, listener);
                self.commands.write().await.send_resolve_request(svc).await;
            }
            Err(id) => {
                services.add_listener(id, listener);
            }
        };
    }

    pub async fn unregister(&self, id: String) {
        info!("Unregister");
        self.advertised_services.write().await.unregister(id);
    }
}

#[derive(Clone)]
struct CommandSender(Vec<mpsc::Sender<Command>>);
impl CommandSender {
    async fn send(&mut self, cmd: Command) {
        for tx in self.0.iter_mut() {
            if let Err(mpsc::error::SendError(_t)) = tx.send(cmd.clone()).await {}
        }
    }

    async fn send_unsolicited(&mut self, svc: ServiceData, ttl: u32, include_ip: bool) {
        info!("Sending unsolicited advertisement {:?}", svc);
        self.send(Command::SendUnsolicited {
            svc,
            ttl,
            include_ip,
        })
        .await;
    }

    async fn send_resolve_request(&mut self, svc: ServiceData) {
        debug!("Sending resolve request ");
        self.send(Command::SendResolveRequest { svc }).await;
    }

    async fn send_shutdown(&mut self) {
        self.send(Command::Shutdown).await;
    }
}
