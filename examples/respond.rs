#[macro_use]
extern crate log;
extern crate env_logger;
extern crate mdns_responder;
use std::env;


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

    
    let _svc = responder.register(
	"_tcp._swir".to_owned(),
	service_name.to_owned(),        
	8080,
	&["path=/"],
    ).await;


    let (sender,receiver) = tokio::sync::mpsc::channel(10);    
    responder.resolve("_tcp._swir".to_owned(),sender ).await;
    
    tokio::spawn(async {
	let mut recv = receiver;
	while let Some(socket) = recv.recv().await{
	    info!("Resolved for {:?} ", socket);
	};	
    });
    
    tokio::time::delay_for(tokio::time::Duration::from_secs(120)).await;
    info!("Shutting down ");
    responder.shutdown().await;

    futures::future::join_all(tasks).await;
    info!("Exiting ... :)");
    
}
