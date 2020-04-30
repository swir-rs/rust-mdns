#[macro_use]
extern crate log;
extern crate env_logger;
extern crate mdns_responder;
use std::env;
use std::net::SocketAddr;


#[tokio::main(core_threads = 1)]
async fn main() {
    let key = "service_name";
    env_logger::init();
    let service_name = if let Ok(service_name)= env::var(key)  {
	info!("Service name {}", service_name);
	service_name
    }else{
	warn!("No service name");
	return;
    };
    
    
    let responder = mdns_responder::Responder::new().unwrap();
    let tasks = responder.start();
    
    let svc = responder.register(
	"_tcp._swir".to_owned(),
	service_name.to_owned(),        
	8080,
	&["path=/"],
    ).await.unwrap();


    let (mut sender1,receiver1) = tokio::sync::mpsc::channel(10);
    let (mut sender2,receiver2) = tokio::sync::mpsc::channel(10);
    
    

    let callback_listener1 = move |fqdn:String, sock:SocketAddr| {	
	let res  = sender1.try_send((fqdn,sock));
	match res{
	    Ok(())=>{ Ok(()) },
	    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {Ok(())},
	    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
		Err(())
	    }
	}	
    };

    let callback_listener2 = move |fqdn:String, sock:SocketAddr| {	
	let res  = sender2.try_send((fqdn,sock));
	match res{
	    Ok(())=>{ Ok(()) },
	    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {Ok(())},
	    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
		Err(())
	    }
	}	
    };
    
    responder.resolve("_tcp._swir".to_owned(),Box::new(callback_listener1)).await;
    responder.resolve("_tcp._swir".to_owned(),Box::new(callback_listener2)).await;
    
    tokio::spawn(async {
	let mut recv = receiver1;
	while let Some(socket) = recv.recv().await{
	    info!("Resolved 1 for {:?} ", socket);
	};	
    });

    tokio::spawn(async {
	let mut recv = receiver2;
	let mut counter =0;
	while let Some(socket) = recv.recv().await{
	    info!("Resolved 2 for {:?} ", socket);
	    counter+=1;
	    if  counter > 5 {		
		info!("Killing 2");
		return
	    }
	};	
    });


    tokio::time::delay_for(tokio::time::Duration::from_secs(120)).await;
    info!("Unregisterting ");
    responder.unregister(svc.id).await;
    tokio::time::delay_for(tokio::time::Duration::from_secs(20)).await;
    info!("Shutting down ");
    responder.shutdown().await;

    futures::future::join_all(tasks).await;
    info!("Exiting ... :)");
    
}
