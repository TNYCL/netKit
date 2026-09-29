use netkit::discovery::*;
use std::{
    net::{TcpListener, UdpSocket},
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::Duration,
};

#[test]
fn port_selection_and_ipv6_scope_are_bounded() {
    assert_eq!(
        parse_ports("443,80,80,100-102").unwrap(),
        vec![80, 100, 101, 102, 443]
    );
    for bad in ["0", "70000", "80-1", "", "-1"] {
        assert!(parse_ports(bad).is_err());
    }
    assert_eq!(targets("192.0.2.0/30", 10).unwrap().len(), 2);
    assert_eq!(targets("::1", 10).unwrap().len(), 1);
    assert!(targets("2001:db8::/64", 256).is_err());
}
#[test]
fn tcp_open_and_unanswered_ports_are_distinct() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut options = ScanOptions {
        addresses: vec!["127.0.0.1".parse().unwrap()],
        ports: vec![port],
        timeout: Duration::from_millis(300),
        ..Default::default()
    };
    let mut results = Vec::new();
    scan(&options, Arc::new(AtomicBool::new(false)), |r| {
        results.push(r)
    })
    .unwrap();
    assert_eq!(results[0].state, "open");
    drop(listener);
    results.clear();
    options.rate_per_second = 1000;
    scan(&options, Arc::new(AtomicBool::new(false)), |r| {
        results.push(r)
    })
    .unwrap();
    // Windows filtering can suppress a local reset, so a timeout is valid
    // evidence. It must never be reported as an open port.
    assert!(matches!(
        results[0].state.as_str(),
        "closed" | "no_response"
    ));
}
#[test]
fn udp_reply_proves_open_but_silence_does_not_prove_closed() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let peer = thread::spawn(move || {
        let mut b = [0; 32];
        let (_, address) = socket.recv_from(&mut b).unwrap();
        socket.send_to(b"test", address).unwrap();
    });
    let options = ScanOptions {
        addresses: vec!["127.0.0.1".parse().unwrap()],
        ports: vec![port],
        transport: ScanTransport::Udp,
        timeout: Duration::from_millis(500),
        ..Default::default()
    };
    let mut results = Vec::new();
    scan(&options, Arc::new(AtomicBool::new(false)), |r| {
        results.push(r)
    })
    .unwrap();
    peer.join().unwrap();
    assert_eq!(results[0].state, "open");
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let options = ScanOptions {
        ports: vec![silent.local_addr().unwrap().port()],
        timeout: Duration::from_millis(50),
        ..options
    };
    results.clear();
    scan(&options, Arc::new(AtomicBool::new(false)), |r| {
        results.push(r)
    })
    .unwrap();
    assert_eq!(results[0].state, "open_or_filtered");
}
#[test]
fn pre_cancelled_scan_sends_no_probes() {
    let options = ScanOptions {
        addresses: vec!["127.0.0.1".parse().unwrap()],
        ..Default::default()
    };
    let mut n = 0;
    scan(&options, Arc::new(AtomicBool::new(true)), |_| n += 1).unwrap();
    assert_eq!(n, 0);
}
