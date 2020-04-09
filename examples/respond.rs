#[macro_use]
extern crate log;
extern crate env_logger;
extern crate mdns_responder;

pub fn main() {
    env_logger::init();

    let responder = mdns_responder::Responder::new().unwrap();
    debug!("Register");
    
    let _svc = responder.register(
        "swir".to_owned(),
        "blah".to_owned(),
        8080,
        &["path=/"],
    );

    loop {
        ::std::thread::sleep(::std::time::Duration::from_secs(10));
    }
}
