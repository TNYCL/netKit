use netkit::capture::{CaptureOptions, Pcap};
#[test]
#[ignore = "compile mock_pcap.c and set NETKIT_TEST_PCAP to its absolute library path"]
fn native_capture_abi_ownership_and_error_paths() {
    let path = std::env::var_os("NETKIT_TEST_PCAP").expect("NETKIT_TEST_PCAP missing");
    let path = std::path::Path::new(&path);
    // SAFETY: this test loads our compiled fixture with the declared C signature.
    let library = unsafe { libloading::Library::new(path) }.unwrap();
    let count =
        unsafe { library.get::<unsafe extern "C" fn() -> i32>(b"mock_live_handles\0") }.unwrap();
    let pcap = Pcap::load_from(Some(path)).unwrap();
    assert!(pcap.version().contains("synthetic"));
    let interfaces = pcap.interfaces().unwrap();
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].monitor_mode, Some(false));
    assert_eq!(unsafe { count() }, 0);
    let mut options = CaptureOptions {
        interface: "synthetic0".into(),
        filter: Some("tcp".into()),
        ..Default::default()
    };
    {
        let mut capture = pcap.open(&options).unwrap();
        assert_eq!(unsafe { count() }, 1);
        let packet = capture.next_packet().unwrap().unwrap();
        assert_eq!(packet.timestamp_ns, 123_000_456_000);
        assert_eq!(packet.data, [1, 2, 3, 4]);
        assert!(capture.next_packet().unwrap().is_none());
        assert_eq!(capture.statistics().unwrap().interface_dropped, 3);
    }
    assert_eq!(unsafe { count() }, 0);
    options.filter = Some("reject".into());
    assert!(pcap.open(&options).is_err());
    assert_eq!(unsafe { count() }, 0);
    options.filter = None;
    options.monitor = true;
    assert!(pcap.open(&options).is_err());
    assert_eq!(unsafe { count() }, 0);
    options.monitor = false;
    options.interface = "invalid-metadata".into();
    let mut capture = pcap.open(&options).unwrap();
    // The handle keeps its library alive even after the Pcap owner is dropped.
    drop(pcap);
    assert!(capture.next_packet().is_err());
    drop(capture);
    assert_eq!(unsafe { count() }, 0);
}
