//! Integration test: transport layer end-to-end.
//!
//! Tests InProcessTransport + codec working together to simulate
//! host ↔ client communication without TCP or Tor.

use sanctum_infra::codec::{Frame, message_types};
use sanctum_infra::transport::InProcessTransport;

// ---------- Full exchange simulation ----------

#[tokio::test]
async fn host_client_handshake_simulation() {
    let (host_side, client_side) = InProcessTransport::pair();

    // Client sends handshake init
    let init = Frame::new(message_types::HANDSHAKE_INIT, vec![1, 2, 3]);
    client_side.send(init.clone()).await.unwrap();

    // Host receives it
    let received = host_side.recv().await.unwrap();
    assert_eq!(received.message_type, message_types::HANDSHAKE_INIT);
    assert_eq!(received.payload, vec![1, 2, 3]);

    // Host sends handshake response
    let resp = Frame::new(message_types::HANDSHAKE_RESP, vec![4, 5, 6]);
    host_side.send(resp.clone()).await.unwrap();

    // Client receives it
    let received = client_side.recv().await.unwrap();
    assert_eq!(received.message_type, message_types::HANDSHAKE_RESP);
    assert_eq!(received.payload, vec![4, 5, 6]);
}

// ---------- Auth flow simulation ----------

#[tokio::test]
async fn auth_challenge_response_over_transport() {
    let (host_side, client_side) = InProcessTransport::pair();

    // Host sends challenge
    let challenge = Frame::new(message_types::AUTH_CHALLENGE, b"nonce+timestamp+room+server".to_vec());
    host_side.send(challenge).await.unwrap();

    // Client receives and responds
    let received = client_side.recv().await.unwrap();
    assert_eq!(received.message_type, message_types::AUTH_CHALLENGE);

    let response = Frame::new(message_types::AUTH_RESPONSE, b"fp+sig+pk+alias".to_vec());
    client_side.send(response).await.unwrap();

    // Host receives response
    let received = host_side.recv().await.unwrap();
    assert_eq!(received.message_type, message_types::AUTH_RESPONSE);

    // Host sends auth result
    let result = Frame::new(message_types::AUTH_RESULT, b"OK".to_vec());
    host_side.send(result).await.unwrap();

    let received = client_side.recv().await.unwrap();
    assert_eq!(received.message_type, message_types::AUTH_RESULT);
}

// ---------- Message routing simulation ----------

#[tokio::test]
async fn message_routing_three_clients() {
    // Host has 3 InProcessTransports (one per client)
    let (host_a, client_a) = InProcessTransport::pair();
    let (host_b, client_b) = InProcessTransport::pair();
    let (host_c, client_c) = InProcessTransport::pair();

    // Client A sends a message
    let msg = Frame::new(message_types::ROOM_MESSAGE, b"hello from A".to_vec());
    client_a.send(msg.clone()).await.unwrap();

    // Host receives from A
    let received = host_a.recv().await.unwrap();
    assert_eq!(received.payload, b"hello from A");

    // Host routes to B and C (not back to A)
    host_b.send(received.clone()).await.unwrap();
    host_c.send(received.clone()).await.unwrap();

    // B and C receive
    let b_msg = client_b.recv().await.unwrap();
    let c_msg = client_c.recv().await.unwrap();
    assert_eq!(b_msg.payload, b"hello from A");
    assert_eq!(c_msg.payload, b"hello from A");
}

// ---------- Keepalive ping/pong ----------

#[tokio::test]
async fn ping_pong_exchange() {
    let (host_side, client_side) = InProcessTransport::pair();

    // Client sends ping
    let ping = Frame::new(message_types::PING, vec![]);
    client_side.send(ping).await.unwrap();

    // Host receives ping, responds with pong
    let received = host_side.recv().await.unwrap();
    assert_eq!(received.message_type, message_types::PING);

    let pong = Frame::new(message_types::PONG, vec![]);
    host_side.send(pong).await.unwrap();

    let received = client_side.recv().await.unwrap();
    assert_eq!(received.message_type, message_types::PONG);
}

// ---------- Large message ----------

#[tokio::test]
async fn large_message_delivery() {
    let (host_side, client_side) = InProcessTransport::pair();

    // 60KB payload (just under the 64KB frame limit)
    let payload = vec![0xABu8; 60_000];
    let frame = Frame::new(message_types::ROOM_MESSAGE, payload.clone());
    client_side.send(frame).await.unwrap();

    let received = host_side.recv().await.unwrap();
    assert_eq!(received.payload.len(), 60_000);
    assert_eq!(received.payload, payload);
}

// ---------- Error frame ----------

#[tokio::test]
async fn error_frame_delivery() {
    let (host_side, client_side) = InProcessTransport::pair();

    let error = Frame::new(message_types::ERROR, b"protocol version mismatch".to_vec());
    host_side.send(error).await.unwrap();

    let received = client_side.recv().await.unwrap();
    assert_eq!(received.message_type, message_types::ERROR);
    assert_eq!(String::from_utf8_lossy(&received.payload), "protocol version mismatch");
}

// ---------- Channel closed detection ----------

#[tokio::test]
async fn detect_closed_channel() {
    let (host_side, client_side) = InProcessTransport::pair();

    // Drop host side
    drop(host_side);

    // Client should get error on recv
    let result = client_side.recv().await;
    assert!(result.is_err(), "should detect closed channel");
}

// ---------- Concurrent send/recv ----------

#[tokio::test]
async fn concurrent_bidirectional_traffic() {
    let (host_side, client_side) = InProcessTransport::pair();

    let host_side = std::sync::Arc::new(host_side);
    let client_side = std::sync::Arc::new(client_side);

    let hs = host_side.clone();
    let cs = client_side.clone();

    // Host sends 10 messages while client sends 10 messages
    let host_task = tokio::spawn(async move {
        for i in 0..10u8 {
            hs.send(Frame::new(message_types::ROOM_MESSAGE, vec![i])).await.unwrap();
        }
    });

    let client_task = tokio::spawn(async move {
        for i in 100..110u8 {
            cs.send(Frame::new(message_types::ROOM_MESSAGE, vec![i])).await.unwrap();
        }
    });

    host_task.await.unwrap();
    client_task.await.unwrap();

    // Receive all on both sides
    let mut host_received = Vec::new();
    for _ in 0..10 {
        host_received.push(host_side.recv().await.unwrap().payload[0]);
    }

    let mut client_received = Vec::new();
    for _ in 0..10 {
        client_received.push(client_side.recv().await.unwrap().payload[0]);
    }

    host_received.sort();
    client_received.sort();

    assert_eq!(host_received, (100..110).collect::<Vec<u8>>());
    assert_eq!(client_received, (0..10).collect::<Vec<u8>>());
}