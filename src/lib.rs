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
use futures::{Future};


use futures::channel::mpsc;
use std::cell::RefCell;
use std::io;
use std::sync::{Arc, RwLock};


mod address_family;
mod fsm;
#[cfg(windows)]
#[path = "netwin.rs"]
mod net;
#[cfg(not(windows))]
mod net;
mod services;

use address_family::{Inet, Inet6};
use fsm::{Command, FSM};
use services::{ServiceData, Services, ServicesInner};

const DEFAULT_TTL: u32 = 60;
const MDNS_PORT: u16 = 5353;

pub struct Responder {
    services: Services,
    commands: RefCell<CommandSender>,
    shutdown: Arc<Shutdown>,
}

pub struct Service {
    id: usize,
    services: Services,
    commands: CommandSender,
    _shutdown: Arc<Shutdown>,
}

impl Responder {   
    pub fn new() -> io::Result<Responder> {
        let mut hostname = net::gethostname()?;
        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        let services = Arc::new(RwLock::new(ServicesInner::new(hostname)));

        let v4 = FSM::<Inet>::new(&services);
        let v6 = FSM::<Inet6>::new(&services);

        let commands = match (v4, v6) {
            (Ok(v4_command), Ok(v6_command)) => {
                vec![v4_command, v6_command]
            },

            (Ok(v4_command), Err(_)) => {
		vec![v4_command]
            }

            (Err(err), _) => return Err(err),
        };

        let commands = CommandSender(commands);
        let responder = Responder {
            services: services,
            commands: RefCell::new(commands.clone()),
            shutdown: Arc::new(Shutdown(commands)),
        };

        Ok(responder)
    }
}

impl Responder {
    pub fn register(&self, svc_type: String, svc_name: String, port: u16, txt: &[&str]) -> Service {
	debug!("Register");
        let txt = if txt.is_empty() {
            vec![0]
        } else {
            txt.into_iter()
                .flat_map(|entry| {
                    let entry = entry.as_bytes();
                    if entry.len() > 255 {
                        panic!("{:?} is too long for a TXT record", entry);
                    }
                    std::iter::once(entry.len() as u8).chain(entry.into_iter().cloned())
                })
                .collect()
        };

        let svc = ServiceData {
            typ: Name::from_str(format!("{}.local", svc_type)).unwrap(),
            name: Name::from_str(format!("{}.{}.local", svc_name, svc_type)).unwrap(),
            port: port,
            txt: txt,
        };

        self.commands
            .borrow_mut()
            .send_unsolicited(svc.clone(), DEFAULT_TTL, true);

        let id = self.services.write().unwrap().register(svc);

        Service {
            id: id,
            commands: self.commands.borrow().clone(),
            services: self.services.clone(),
            _shutdown: self.shutdown.clone(),
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let svc = self.services.write().unwrap().unregister(self.id);
        self.commands.send_unsolicited(svc, 0, false);
    }
}

struct Shutdown(CommandSender);

impl Drop for Shutdown {
    fn drop(&mut self) {
        self.0.send_shutdown();
        // TODO wait for tasks to shutdown
    }
}

#[derive(Clone)]
struct CommandSender(Vec<mpsc::UnboundedSender<Command>>);
impl CommandSender {
    fn send(&mut self, cmd: Command) {
        for tx in self.0.iter_mut() {
            tx.unbounded_send(cmd.clone()).expect("responder died");
        }
    }

    fn send_unsolicited(&mut self, svc: ServiceData, ttl: u32, include_ip: bool) {
        self.send(Command::SendUnsolicited {
            svc: svc,
            ttl: ttl,
            include_ip: include_ip,
        });
    }

    fn send_shutdown(&mut self) {
        self.send(Command::Shutdown);
    }
}
