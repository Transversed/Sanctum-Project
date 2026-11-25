//! Relay resource limits (P5.2): handshake timeout, idle timeout,
//! connection cap.

use sanctum_domain::entities::room::RoomConfig;
use sanctum_infra::codec;
use sanctum_infra::host_listener::HostLimits;
use sanctum_infra::testkit::TestHost;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};

fn limits(handshake: u64, idle: u64, max: usize) -> HostLimits {
    HostLimits {
        handshake_timeout: Duration::from_secs(handshake),
        idle_timeout: Duration::from_secs(idle),
        max_connections: max,
    }
}

/// Wait until the peer closes the socket; returns the elapsed time.
async fn closed_after(stream: &mut TcpStream, max: Duration) -> Option<Duration> {
    let start = Instant::now();
    let mut buf = [0u8; 64];
    loop {
        match timeout(max.saturating_sub(start.elapsed()), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Some(start.elapsed()),
            Ok(Ok(_)) => continue,
            Err(_) => return None,
        }
    }
}

#[tokio::test]
async fn silent_tcp_connection_is_closed_after_the_handshake_timeout() {
    let host = TestHost::start_with(RoomConfig::default(), limits(1, 60, 8)).await;
    let mut silent = TcpStream::connect(&host.addr).await.unwrap();
    let t = closed_after(&mut silent, Duration::from_secs(5))
        .await
        .expect("connection must be closed");
    assert!(t < Duration::from_secs(3), "closed after {t:?}");
}

#[tokio::test]
async fn silent_member_is_disconnected_after_the_idle_timeout() {
    let host = TestHost::start_with(RoomConfig::default(), limits(5, 1, 8)).await;
    let (_, mut quiet) = host.join("quiet").await;
    let start = Instant::now();
    let mut closed = false;
    while start.elapsed() < Duration::from_secs(5) {
        match timeout(Duration::from_millis(200), quiet.transport.recv_frame()).await {
            Ok(Err(_)) => {
                closed = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(closed, "idle member must be disconnected");
}

#[tokio::test]
async fn pinging_member_stays_connected() {
    let host = TestHost::start_with(RoomConfig::default(), limits(5, 1, 8)).await;
    let (_, mut active) = host.join("active").await;
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        active
            .transport
            .send_frame(&codec::ping_frame())
            .await
            .unwrap();
        let pong = timeout(Duration::from_secs(1), active.transport.recv_frame())
            .await
            .expect("pong in time")
            .expect("still connected");
        assert_eq!(pong.message_type, codec::message_types::PONG);
    }
}

#[tokio::test]
async fn connections_over_the_cap_are_closed_immediately() {
    let host = TestHost::start_with(RoomConfig::default(), limits(5, 60, 2)).await;
    let _a = TcpStream::connect(&host.addr).await.unwrap();
    let _b = TcpStream::connect(&host.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c = TcpStream::connect(&host.addr).await.unwrap();
    let t = closed_after(&mut c, Duration::from_secs(3))
        .await
        .expect("third connection must be refused");
    assert!(t < Duration::from_secs(1));
}
