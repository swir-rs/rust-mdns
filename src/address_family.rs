use super::MDNS_PORT;
#[cfg(not(windows))]
use net2::unix::UnixUdpBuilderExt;
use net2::UdpBuilder;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

#[derive(Clone)]
pub struct Inet();
#[derive(Clone)]
pub struct Inet6();

pub trait AddressFamily {
    fn bind(&self) -> io::Result<UdpSocket> {
        let addr = SocketAddr::new(self.any_addr(), MDNS_PORT);
        let builder = self.socket_builder()?;
        builder.reuse_address(true)?;
        #[cfg(not(windows))]
        let _ = builder.reuse_port(true);
        let socket = builder.bind(&addr)?;
        self.join_multicast(&socket)?;
        Ok(socket)
    }

    fn socket_builder(&self) -> io::Result<UdpBuilder>;
    fn any_addr(&self) -> IpAddr;
    fn mdns_group(&self) -> IpAddr;
    fn join_multicast(&self, socket: &UdpSocket) -> io::Result<()>;
    fn v6(&self) -> bool;
}

impl AddressFamily for Inet {
    fn socket_builder(&self) -> io::Result<UdpBuilder> {
        UdpBuilder::new_v4()
    }
    fn any_addr(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    }
    fn mdns_group(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))
    }
    fn join_multicast(&self, socket: &UdpSocket) -> io::Result<()> {
        socket.set_multicast_loop_v4(true)?;
        socket.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &Ipv4Addr::new(0, 0, 0, 0))
    }
    fn v6(&self) -> bool {
        false
    }
}

impl AddressFamily for Inet6 {
    fn socket_builder(&self) -> io::Result<UdpBuilder> {
        UdpBuilder::new_v6()
    }
    fn any_addr(&self) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
    }
    fn mdns_group(&self) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb))
    }
    fn join_multicast(&self, socket: &UdpSocket) -> io::Result<()> {
        socket.set_multicast_loop_v6(true)?;
        socket.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 0)
    }
    fn v6(&self) -> bool {
        true
    }
}
