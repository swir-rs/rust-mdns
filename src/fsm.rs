use dns_parser::{self,Name, QueryClass, QueryType, RRData};
use tokio::sync::mpsc;
use get_if_addrs::get_if_addrs;
use futures::StreamExt;

use std::io;

use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::net::udp::{SendHalf, RecvHalf};
use crate::record::Response;

use super::{DEFAULT_TTL, MDNS_PORT};
use crate::address_family::AddressFamily;
use crate::services::{ServiceData, Services};

use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration,timeout};

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
    SendResolveRequest {
        svc: ServiceData,
    },
    
    Shutdown,
}

pub struct FSM {
    state:Arc<RwLock<FSMState>>,
    recv_half:Arc<RwLock<RecvHalf>>,
    send_half:Arc<RwLock<SendHalf>>,
    mdns_group: IpAddr,
    af_v6: bool,
    advertised_services: Services,
    resolved_services: Services,
    commands: Arc<RwLock<mpsc::Receiver<Command>>>,
    outgoing: mpsc::Sender<Command>
}

fn parse_service_name<'a>(service: String )-> (String,Option<String>) {
    let service = service.to_string();
    let ind = service.find(".");
    let service_type;
    if let Some(i) = ind{

	    if service.ends_with(".local"){
//	        service_type = Some(String::from(&service[(i+1)..(service.len()-".local".len())]));
		service_type = Some(String::from(&service[(i+1)..]));
	    }else{
	        service_type = Some(String::from(&service[(i+1)..]));
	    }
	}else{
	
	    service_type=None;
    }
    (service, service_type)
}

async fn handle_question(
    af_v6:bool,
    services: &Services,
    question: & dns_parser::Question<'_>,
    mut builder: AnswerBuilder,
) -> AnswerBuilder {
    let services = services.read().await;
    match question.qtype {
        QueryType::A | QueryType::AAAA | QueryType::All
            if question.qname == *services.get_hostname() =>
        {
            builder = add_ip_rr(af_v6,services.get_hostname(), builder, DEFAULT_TTL);
        }
        QueryType::PTR => {
            for svc in services.find_by_type(&question.qname) {
                builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
                builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                builder = add_ip_rr(af_v6,services.get_hostname(), builder, DEFAULT_TTL);
            }
        }
        QueryType::SRV => {
            if let Some(svc) = services.find_by_name(&question.qname) {
		builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                builder = svc.add_srv_rr(services.get_hostname(), builder, DEFAULT_TTL);
		builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                builder = add_ip_rr(af_v6,services.get_hostname(), builder, DEFAULT_TTL);
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

fn add_ip_rr(af_v6: bool, hostname: &Name, mut builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
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
            IpAddr::V4(ip) if !af_v6 => {
                builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::A(ip))
            }
            IpAddr::V6(ip) if af_v6 => {
                builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::AAAA(ip))
            }
            _ => (),
        }
    }

    builder
}


async fn handle_resolve_response(services:Services, packet: dns_parser::Packet<'_>,  addr: SocketAddr)->Option<Vec<u8>> {
    
    if packet.header.truncated {
        warn!("handle_resolve_response : dropping truncated packet from {:?}", addr);
        return None;
    }
    let response = Response::from_packet(&packet);
    let ip = response.ip_addr();
    let port = response.port();
    let service = response.hostname();

    
    debug!("handle_resolve_response :  Handling resolve response : query {} resolved IP {:?} port {:?} service {:?}", packet.header.query, ip, port, service);
    match (ip, port, service){
	(Some(ip), Some(port), Some(service))=>{
	    let (service_name, service_type) = parse_service_name(service);
	    debug!("handle_resolve_response : service_type {:?}", service_type);
	    if let Some(service_type) = service_type{
		if let Ok(svc_type) = Name::from_str(service_type){
		    let mut services = services.write().await;
		    services.send_notification(&svc_type,service_name,SocketAddr::from((ip.clone(),port)));				
		}
	    }
	},
	 _ => {}
    };
    
    
    None
}

async fn handle_resolve_request(af_v6: bool, services:Services, packet: dns_parser::Packet<'_>,  addr: SocketAddr)->Option<Vec<u8>> {
    if packet.header.truncated {
        warn!("handle_resolve_request : dropping truncated packet from {:?}", addr);
        return None;
    }

    let mut unicast_builder = dns_parser::Builder::new_response(packet.header.id, false)
        .move_to::<dns_parser::Answers>();
    let mut multicast_builder = dns_parser::Builder::new_response(packet.header.id, false)
        .move_to::<dns_parser::Answers>();
    unicast_builder.set_max_size(None);
    multicast_builder.set_max_size(None);

    for question in packet.questions {
        debug!(
            "handle_resolve_request : received question: {:?} {}",
            question.qclass, question.qname
        );

        if question.qclass == QueryClass::IN || question.qclass == QueryClass::Any {
            if question.qu {
                unicast_builder = handle_question(af_v6,&services,&question, unicast_builder).await;
            } else {
                multicast_builder = handle_question(af_v6,&services, &question, multicast_builder).await;
            }
        }
    }

    let mut res = None;
    if !multicast_builder.is_empty() {
        let response = multicast_builder.build().unwrap_or_else(|x| x);
        res = Some(response);	    
    }else{
	trace!("handle_resolve_request : Multicast builder is empty");
    }

    if !unicast_builder.is_empty() {
        let response = unicast_builder.build().unwrap_or_else(|x| x);
	res = Some(response);
    }else{
	trace!("handle_resolve_request : Unicast builder is empty");
    }
    res

}

async fn receive(recv_half:Arc<RwLock<RecvHalf>>,af_v6:bool, advertised_services: Services, resolved_services: Services, mut outgoing:mpsc::Sender<Command>,state: Arc<RwLock<FSMState>>){
    debug!("received : entered");
    let mut socket_rx = recv_half.write().await;        	
    loop{	
	let state = state.read().await;
	match *state{
	    FSMState::Closed=>{
		info!("receive: exited FSM is closed");
		return;
	    },
	    _ => {}	    
	}

	let mut buf = [0u8; 4096];	
	let res = timeout(Duration::from_secs(5),socket_rx.recv_from(&mut buf)).await;
	let advertised_services= advertised_services.clone();
	let resolved_services= resolved_services.clone();
	match res{
	    Ok(Ok((bytes, addr)))=>{
		if bytes > buf.len(){
		    warn!("Discarding as packet with {} bytes is too long for the buffer {}",bytes, buf.len());
		};
		trace!("Received packet {:x?}",&buf[..bytes]);

		match dns_parser::Packet::parse(&buf[..bytes]){		    
		    Ok(packet) => {
			debug!("received packet from {:?} with header {:?} ", addr, packet.header);		    
			if packet.header.query {
			    let res = handle_resolve_request(af_v6,advertised_services,packet,addr).await;
			    if let Some(response) = res{
				let res = outgoing.send(Command::SendResponse{response, addr}).await;
				if let Err(e)= res{
				    info!("Can't send {:?}",e);
				    return;
				}
			    }		    		    		    			    
			}else{
			    let _res = handle_resolve_response(resolved_services,packet,addr).await;
			}
		    },
		    Err(error) => {
			warn!("couldn't parse packet from {:?}: {}", addr, error);			
		    }
		};										
	    },
	    Ok(Err(e))=>{
		info!("Socket terminated {:?}",e);
		return;
	    }
	    Err(e)=> {
		trace!("Timeout {:?}",e);
	    }	   	    
	}
    }

}

fn prepare_unsolicited(af_v6:bool, mdns_group:IpAddr, hostname: &dns_parser::Name<'_>, svc: &ServiceData, ttl: u32, include_ip: bool) ->Option<(Vec<u8>,SocketAddr)>{
    let mut builder =
        dns_parser::Builder::new_response(0, false).move_to::<dns_parser::Answers>();
    builder.set_max_size(None);
    debug!("prepare_unsolicited {} {} ",af_v6, mdns_group);

    builder = svc.add_ptr_rr(builder, ttl);
    builder = svc.add_srv_rr(hostname, builder, ttl);
    builder = svc.add_txt_rr(builder, ttl);
    if include_ip {
	builder = add_ip_rr(af_v6, hostname, builder, ttl);
    }    
    if !builder.is_empty() {
        Some((builder.build().unwrap_or_else(|x| x),SocketAddr::new(mdns_group, MDNS_PORT)))
    }else{
	None
    }
    
}

fn prepare_resolve_request(af_v6:bool, mdns_group:IpAddr, svc: &ServiceData) ->Option<(Vec<u8>,SocketAddr)>{    
    let mut builder = dns_parser::Builder::new_query(0, false).move_to::<dns_parser::Questions>();
    builder.set_max_size(None);
    debug!("prepare_resolve_request {} {} {:?}",af_v6, mdns_group,svc);
    builder = svc.add_ptr_rq(builder);
    Some((builder.build().unwrap_or_else(|x| x),SocketAddr::new(mdns_group, MDNS_PORT)))
}




async fn send_response(send_half:&Arc<RwLock<SendHalf>>, data: Vec<u8>, addr: SocketAddr) {
    let mut send_half = send_half.write().await;
    let res = send_half.send_to(&data,&addr).await;
    if let Err(e) = res{
	warn!("Can't send {:?}",e);
    };
}

async fn send(send_half:Arc<RwLock<SendHalf>>,af_v6: bool, mdns_group: IpAddr, services: Services,commands: Arc<RwLock<mpsc::Receiver<Command>>>,state: Arc<RwLock<FSMState>>  ){
    debug!("send: entered");
    let mut commands = commands.write().await;
    while let Some(command) = commands.next().await{
	let services= services.clone();
	match command{
	    Command::Shutdown =>{
		debug!("send: Shutting down");
		let mut state = state.write().await;
		*state = FSMState::Closed;
		commands.close();
		debug!("send: exited by return ");
		return;
	    },
	    Command::SendUnsolicited{
		svc,ttl,include_ip
	    }=>{
		let services = services.read().await;
		let hostname = services.get_hostname();
		if let Some((response,addr)) = prepare_unsolicited(af_v6, mdns_group, hostname, &svc, ttl, include_ip){
		    send_response(&send_half,response,addr).await;
		}
		
	    },

	    Command::SendResponse{response, addr}=>{
		send_response(&send_half,response,addr).await;		    		    		    
	    },
	    Command::SendResolveRequest{
		svc
	    }=>{		
		if let Some((response,addr)) = prepare_resolve_request(af_v6, mdns_group, &svc){
		    send_response(&send_half,response,addr).await;
		}
	    }		    			    			
	}
	
    }
    debug!("send: exited");
}

enum FSMState{
    Active,
    Closed
}

impl FSM{
    pub fn new(
        advertised_services: &Services,resolved_services: &Services, af: impl AddressFamily
    ) -> io::Result<(Self,mpsc::Sender<Command>)> {
        let std_socket = af.bind()?;
        let socket = UdpSocket::from_std(std_socket).unwrap();
	let (recv_half, send_half) = socket.split(); 
        let (tx, rx) = mpsc::channel(10);

        let fsm = FSM{
	    state : Arc::new(RwLock::new(FSMState::Active)),
	    recv_half: Arc::new(RwLock::new(recv_half)),
	    send_half: Arc::new(RwLock::new(send_half)),
	    mdns_group: af.mdns_group(),
	    af_v6:af.v6(),
            advertised_services: advertised_services.clone(),
	    resolved_services: resolved_services.clone(),
            commands: Arc::new(RwLock::new(rx)),
            outgoing: tx.clone(),
        };
	Ok((fsm,tx))
    }

    pub fn start(&self)->(tokio::task::JoinHandle<()>,tokio::task::JoinHandle<()>){	
	let send_half=  self.send_half.clone();
	let advertised_services = self.advertised_services.clone();
	let commands = self.commands.clone();
	let af_v6 = self.af_v6;
	let mdns_group = self.mdns_group;
	let state = self.state.clone();
	let send_task = async move{	    
	    send(send_half,af_v6,mdns_group,advertised_services,commands,state).await;
	};


	let recv_half=  self.recv_half.clone();
	let advertised_services = self.advertised_services.clone();
	let resolved_services = self.resolved_services.clone();
	let outgoing = self.outgoing.clone();
	let state = self.state.clone();
	let receive_task = async move{
	    receive(recv_half,af_v6,advertised_services,resolved_services,outgoing,state).await;
	};

	
	let receive_task_handle = tokio::spawn(receive_task);
	let send_task_handle = tokio::spawn(send_task);
	
	(receive_task_handle,send_task_handle)
    }
        
}


