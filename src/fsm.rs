use dns_parser::{self, Name, QueryClass, QueryType, RRData};
use futures::channel::mpsc;
use get_if_addrs::get_if_addrs;
use crate::futures::stream::StreamExt;
use crate::futures::SinkExt;
use std::io;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::net::udp::{SendHalf, RecvHalf};

use super::{DEFAULT_TTL, MDNS_PORT};
use crate::address_family::AddressFamily;
use crate::services::{ServiceData, Services};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

#[derive(Clone, Debug)]
pub enum Command {
    SendUnsolicited {
        svc: ServiceData,
        ttl: u32,
        include_ip: bool,
    },
    SendResponse {
        response : Vec<u8>,
        addr: SocketAddr
    },
	    
    Shutdown,
}

pub struct FSM<AF: AddressFamily> {
    recv_half:RecvHalf,
    send_half:SendHalf,
    services: Services,
    commands: mpsc::UnboundedReceiver<Command>,
    outgoing: mpsc::UnboundedSender<Command>,
    _af: PhantomData<AF>,
}

impl<AF: AddressFamily> FSM<AF> {
    pub fn new(
        services: &Services,
    ) -> io::Result<mpsc::UnboundedSender<Command>> {
        let std_socket = AF::bind()?;
        let socket = UdpSocket::from_std(std_socket).unwrap();
	let (recv_half, send_half) = socket.split(); 
        let (tx, rx) = mpsc::unbounded();

        let fsm = FSM::<AF>{	              
	    recv_half,
	    send_half,	    
            services: services.clone(),
            commands: rx,
            outgoing: tx.clone(),
            _af: PhantomData,
        };
	Ok(tx)
    }

    async fn handle_packet(&mut self, buffer: &[u8], addr: SocketAddr) {
        debug!("received packet from {:?}", addr);
	
        let packet = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => packet,
            Err(error) => {
                warn!("couldn't parse packet from {:?}: {}", addr, error);
                return;
            }
        };

	debug!("received header {:?} with  {:?}", packet.header,addr);
        if !packet.header.query {
            warn!("received packet from {:?} with no query", addr);
            return;
        }

        if packet.header.truncated {
            warn!("dropping truncated packet from {:?}", addr);
            return;
        }

        let mut unicast_builder = dns_parser::Builder::new_response(packet.header.id, false)
            .move_to::<dns_parser::Answers>();
        let mut multicast_builder = dns_parser::Builder::new_response(packet.header.id, false)
            .move_to::<dns_parser::Answers>();
        unicast_builder.set_max_size(None);
        multicast_builder.set_max_size(None);

        for question in packet.questions {
            debug!(
                "received question: {:?} {}",
                question.qclass, question.qname
            );

            if question.qclass == QueryClass::IN || question.qclass == QueryClass::Any {
                if question.qu {
                    unicast_builder = self.handle_question(&question, unicast_builder);
                } else {
                    multicast_builder = self.handle_question(&question, multicast_builder);
                }
            }
        }

        if !multicast_builder.is_empty() {
            let response = multicast_builder.build().unwrap_or_else(|x| x);
            let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
            let res = self.outgoing.send(Command::SendResponse{response, addr}).await;
	    if let Err(e) = res{
		warn!("Receiving end closed {}",e);
	    }
	    
        }else{
	    debug!("Multicast builder is empty");
	}

        if !unicast_builder.is_empty() {
            let response = unicast_builder.build().unwrap_or_else(|x| x);
	    let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
	    let res = self.outgoing.send(Command::SendResponse{response, addr}).await;
	    if let Err(e) = res{
		warn!("Receiving end closed {}",e);
	    }

        }else{
	    debug!("Unicast builder is empty");
	}
    }

    fn handle_question(
        &self,
        question: &dns_parser::Question,
        mut builder: AnswerBuilder,
    ) -> AnswerBuilder {
        let services = self.services.read().unwrap();
	debug!("Handle question {}",question.qname);
        match question.qtype {
            QueryType::A | QueryType::AAAA | QueryType::All
                if question.qname == *services.get_hostname() =>
            {
                builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
            }
            QueryType::PTR => {
                for svc in services.find_by_type(&question.qname) {
                    builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                    builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
                }
            }
            QueryType::SRV => {
                if let Some(svc) = services.find_by_name(&question.qname) {
		    builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                    builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
		    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(services.get_hostname(), builder, DEFAULT_TTL);
                }
            }
            QueryType::TXT => {
                if let Some(svc) = services.find_by_name(&question.qname) {
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                }
            }
            _ => (),
        }

        builder
    }

    fn add_ip_rr(&self, hostname: &Name, mut builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        let interfaces = match get_if_addrs() {
            Ok(interfaces) => interfaces,
            Err(err) => {
                error!("could not get list of interfaces: {}", err);
                return builder;
            }
        };

        for iface in interfaces {
            if iface.is_loopback() {
                continue;
            }

            trace!("found interface {:?}", iface);
            match iface.ip() {
                IpAddr::V4(ip) if !AF::v6() => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::A(ip))
                }
                IpAddr::V6(ip) if AF::v6() => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::AAAA(ip))
                }
                _ => (),
            }
        }

        builder
    }

    async fn send_unsolicited(&mut self, svc: &ServiceData, ttl: u32, include_ip: bool) {
        let mut builder =
            dns_parser::Builder::new_response(0, false).move_to::<dns_parser::Answers>();
        builder.set_max_size(None);
	debug!("Sending unsolicited method");
	{	    
            let services = self.services.read().unwrap();
            builder = svc.add_ptr_rr(builder, ttl);
            builder = svc.add_srv_rr(services.get_hostname(), builder, ttl);
            builder = svc.add_txt_rr(builder, ttl);
            if include_ip {
		builder = self.add_ip_rr(services.get_hostname(), builder, ttl);
            }
	}

        if !builder.is_empty() {
            let response = builder.build().unwrap_or_else(|x| x);
            let addr = SocketAddr::new(AF::mdns_group(), MDNS_PORT);
            self.send_response(response, addr).await;
        }
    }

    async fn send_response(&mut self,data: Vec<u8>, addr: SocketAddr) {
	let res = self.send_half.send_to(&data,&addr).await;
	if let Err(e) = res{
	    warn!("Can't send {:?}",e);
	};
    }

    async fn send(&mut self){	
	while let Some(command) = self.commands.next().await{
	    match command{
		Command::Shutdown =>{
		    debug!("Shutting down");
		    self.commands.close();
		},
		Command::SendUnsolicited{
		    svc,ttl,include_ip
		}=>{
		    self.send_unsolicited(&svc, ttl, include_ip).await;		    
		    
		},
		Command::SendResponse{response, addr}=>{
		    self.send_response(response,addr).await;		    		    		    
		}		    			    			
	    }
	    
	}	
    }

    async fn receive(&mut self, mut socket_rx :tokio::net::udp::RecvHalf){
	loop{
	    let mut buf = [0u8; 4096];
	    let res = socket_rx.recv_from(&mut buf).await;
	    match res{
		Ok((bytes,addr))=>{
		    if bytes > buf.len(){
			warn!("Discarding as packet with {} bytes is too long for the buffer {}",bytes, buf.len());
		    };
		    trace!("Received packet {:x?}",&buf[..bytes]);
		    self.handle_packet(&buf[..bytes], addr).await;
		    
		    
		    
		},
		Err(e)=> {
		    info!("Socket terminated {:?}",e);
		    return;
		}	   	    
	    }
	
	}
    }
}

// impl<AF: AddressFamily> Future for FSM<AF> {
//     type Output = Result<(),io::Error>;
//     fn poll(mut self: Pin<&mut Self>,cx: &mut Context) -> Poll<Self::Output> {
//         while let cmd= self.commands.try_next().unwrap() {
//             match cmd {
//                 Some(Command::Shutdown) => return Poll::Ready(Ok(())),
//                 Some(Command::SendUnsolicited {
//                     svc,
//                     ttl,
//                     include_ip,
//                 }) => {
// 		    debug!("Sending unsolicited  ?");
//                     self.send_unsolicited(&svc, ttl, include_ip);
//                 }
//                 None => {
//                     warn!("responder disconnected without shutdown");
//                     return Poll::Ready(Ok(()));
//                 }
//             }
//         }
	
//         while let Poll::Ready(Ok(())) = self.socket.poll_read() {
//             self.recv_packets()?;
//         }

//         loop {
//             if let Some(&(ref response, ref addr)) = self.outgoing.front() {
//                 trace!("sending packet to {:?}", addr);

//                 match self.socket.send_to(response, addr) {
//                     Ok(_) => (),
//                     Err(ref ioerr) if ioerr.kind() == WouldBlock => break,
//                     Err(err) => warn!("error sending packet {:?}", err),
//                 }
//             } else {
//                 break;
//             }

//             self.outgoing.pop_front();
//         }

//         Poll::Pending
//     }

// }
