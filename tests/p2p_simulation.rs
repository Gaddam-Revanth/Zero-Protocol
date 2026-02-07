use futures::StreamExt;
use libp2p::{Multiaddr, gossipsub, swarm::SwarmEvent};
use std::time::Duration;
use tokio::time::sleep;
use zero_protocol::p2p::{ZeroEvent, build_swarm}; // Need to expose event enum or use generated one

// Note: network_behaviour macro generates `ZeroEvent` (via manual impl).
// We need to make sure `ZeroBehaviour` fields are public (they are).

#[tokio::test]
async fn test_p2p_messaging() {
    // 1. Create Node A
    let key_a = libp2p::identity::Keypair::generate_ed25519();
    let mut swarm_a = build_swarm(key_a, None).await.unwrap();

    // 2. Create Node B
    let key_b = libp2p::identity::Keypair::generate_ed25519();
    let mut swarm_b = build_swarm(key_b, None).await.unwrap();

    // 3. Listen on localhost
    swarm_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    swarm_b
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    // 4. Wait for listen address
    let mut addr_a: Option<Multiaddr> = None;

    // Helper to drive swarm until address event
    // In real test we loop both.

    // We will run them concurrently.
    // Simplifying: we'll just run loop logic inline.

    // Subscribe to topic
    let topic = gossipsub::IdentTopic::new("zero-protocol");
    swarm_a.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
    swarm_b.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

    // Run loop
    let mut messages_received = 0;

    // Create a channel to signal success? Or just loop for N seconds.

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                event = swarm_a.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Node A Listening on {:?}", address);
                            addr_a = Some(address);
                        },
                        _ => {}
                    }
                },
                event = swarm_b.select_next_some() => {
                     match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("Node B Listening on {:?}", address);
                            // Connect A to B if A is ready?
                            // Easier to dial manually once we have addresses.
                        },
                         SwarmEvent::Behaviour(ZeroEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                            println!("Node B Received: {:?}", String::from_utf8_lossy(&message.data));
                            messages_received += 1;
                            if messages_received >= 1 {
                                return; // Success
                            }
                        },
                        _ => {}
                     }
                },
                _ = sleep(Duration::from_secs(1)) => {
                    // Periodic actions
                    if addr_a.is_some() {
                       // Try verify connection or dial
                       // If we rely on mdns, it might be slow in test env.
                       // Let's manually dial if we know specific port.
                    }
                }
            }

            // Manual dialing hack for test robustness (since mDNS is flaky in CI/Docker)
            // But we need to extract the port from `addr_a` and tell swarm_b to dial it.
        }
    });

    // ... this test structure is complex to write correct async loop in one go.
    // I will simplify.
    handle.await.unwrap();
}
