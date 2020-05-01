extern crate env_logger;
extern crate mdns_responder;

pub fn main() {
    env_logger::init();

    let responder = mdns_responder::Responder::new().unwrap();
    let _svc = responder.register(
        "_swir._tcp".to_owned(),
        "sidecar".to_owned(),
        8080,
        &["path=/"],
    );

    loop {
        ::std::thread::sleep(::std::time::Duration::from_secs(10));
    }
}
