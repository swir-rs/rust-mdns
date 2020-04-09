use dns_parser::{self, Name, QueryClass, RRData};
use multimap::MultiMap;
use std::collections::HashMap;
use std::slice;
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::sync::RwLock;

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;
pub type QuestionBuilder = dns_parser::Builder<dns_parser::Questions>;

/// A collection of registered services is shared between threads.
pub type Services = Arc<RwLock<ServicesInner>>;

pub struct ServicesInner {
    hostname: Name<'static>,
    /// main index
    by_id: HashMap< String, ServiceData>,
    /// maps to id
    by_type: MultiMap<Name<'static>, String>,
    /// maps to id
    by_name: HashMap<Name<'static>, String>,
    pub resolve_listeners: MultiMap<String, tokio::sync::mpsc::Sender<(String,SocketAddr)>>,

}



impl ServicesInner {
    pub fn new(hostname: String) -> Self {
        ServicesInner {
            hostname: Name::from_str(hostname).unwrap(),
            by_id: HashMap::new(),
            by_type: MultiMap::new(),
            by_name: HashMap::new(),
	    resolve_listeners: MultiMap::new(),
        }
    }

    pub fn get_hostname(&self) -> &Name<'static> {
        &self.hostname
    }

    pub fn get_all(&self) -> Vec<ServiceData>{
        self.by_id.iter().map(|(_id, sd)| sd.clone()).collect()
    }


    pub fn find_by_name<'a> (&'a self, name: &'a Name<'a>) -> Option<&ServiceData> {
	self.by_name.get(name).and_then(|id| self.by_id.get(id))
    }
    

    
    pub fn find_by_type<'a> (&'a self, ty: &'a Name<'a>) -> FindByType<'a> {
        let ids = self.by_type.get_vec(ty).map(|ids| ids.iter());

        FindByType {
            services: self,
            ids: ids,
        }
    }

    pub fn register(&mut self, svc: ServiceData) -> Result<String,String>{
	debug!("register");
        let id = svc.svc_name.to_string();
        if self.by_id.contains_key(&id) {
            
        }

        self.by_type.insert(svc.svc_type.clone(), id.clone());
        self.by_name.insert(svc.svc_name.clone(), id.clone());
        self.by_id.insert(id.clone(), svc);
        Ok(id)
    }

    pub fn add_listener(&mut self, id: String, listener: tokio::sync::mpsc::Sender<(String, SocketAddr)>){
	debug!("add_listener");        
        self.resolve_listeners.insert(id.clone(), listener);		   
    }

    pub fn send_notification(&mut self, name: &Name, service_name: String, resolved_ip: SocketAddr){
	debug!("send_notification {:?}", name);

	let id = self.by_name.get(name);

	if let Some(id) = id{
	    let listeners = self.resolve_listeners.get_vec_mut(id).unwrap();
	    let mut closed_channels = vec![];
	    for (i,l) in listeners.iter_mut().enumerate(){
		match l.try_send((service_name.clone(),resolved_ip)){
		    Ok(())=>{},
		    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
			
		    },
		    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
			closed_channels.push(i);
		    },
		}
	    }
	    for i in closed_channels.iter(){
		listeners.remove(*i);	    
	    }
	    let id = id.clone();
	    if listeners.is_empty(){
		self.resolve_listeners.remove(&id);
		self.unregister(id);
	    }
	}else{
	    debug!("Ingoring for {:?}",name );
	}

    }

    
    
    pub fn unregister(&mut self, id: String) -> ServiceData {
        use std::collections::hash_map::Entry;

        let svc = self.by_id.remove(&id).expect("unknown service");

        if let Some(entries) = self.by_type.get_vec_mut(&svc.svc_type) {
            entries.retain(|e| e != &id);
        }

        match self.by_name.entry(svc.svc_name.clone()) {
            Entry::Occupied(entry) => {
                assert_eq!(*entry.get(), id);
                entry.remove();
            }
            _ => {
                panic!("unknown/wrong service for id {}", id);
            }
        }

        svc
    }
}

/// Returned by [`ServicesInner.find_by_type`](struct.ServicesInner.html#method.find_by_type)
pub struct FindByType<'a> {
    services: &'a ServicesInner,
    ids: Option<slice::Iter<'a, String>>,
}

impl<'a> Iterator for FindByType<'a> {
    type Item = &'a ServiceData;

    fn next(&mut self) -> Option<Self::Item> {
        self.ids.as_mut().and_then(Iterator::next).map(|id| {
            let svc = self.services.by_id.get(id);
            svc.expect("missing service")
        })
    }
}



#[derive(Clone, Debug)]
pub struct ServiceData {
    pub svc_name: Name<'static>,
    pub svc_type: Name<'static>,
    pub port: u16,
    pub txt: Vec<u8>,
    
}



/// Packet building helpers for `fsm` to respond with `ServiceData`
impl ServiceData {
    pub fn add_ptr_rr(&self, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(
            &self.svc_type,
            QueryClass::IN,
            ttl,
            &RRData::PTR(self.svc_name.clone()),
        )
    }

    pub fn add_ptr_rq(&self, builder:QuestionBuilder) -> QuestionBuilder {
	builder.add_question(
            &self.svc_type,
            dns_parser::QueryType::PTR,
            dns_parser::QueryClass::IN,	    
        )
    }

    pub fn add_srv_rr(&self, hostname: &Name, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(
            &self.svc_name,
            QueryClass::IN,
            ttl,
            &RRData::SRV {
                priority: 0,
                weight: 0,
                port: self.port,
                target: hostname.clone(),
            },
        )
    }

    pub fn add_txt_rr(&self, builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        builder.add_answer(&self.svc_name, QueryClass::IN, ttl, &RRData::TXT(&self.txt))
    }
}
