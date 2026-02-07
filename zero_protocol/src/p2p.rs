use libp2p::{PeerId, Transport, gossipsub, kad, mdns, noise, swarm::NetworkBehaviour, tcp, yamux};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::io;

#[derive(NetworkBehaviour)]
pub struct ZeroBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
}

pub async fn build_swarm(
    local_key: libp2p::identity::Keypair,
) -> Result<libp2p::Swarm<ZeroBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(local_key.public());

    // 1. Configure Transport (TCP + Noise + Yamux)
    let tcp_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::Config::new(&local_key)?)
        .multiplex(yamux::Config::default())
        .boxed();

    // 2. Configure Gossipsub with Reputation System (Peer Scoring)
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    // Reputation Logic (Mutable Init to avoid version mismatch)
    let mut topic_score_params = gossipsub::TopicScoreParams::default();
    topic_score_params.topic_weight = 1.0;
    topic_score_params.time_in_mesh_weight = 0.01;
    topic_score_params.time_in_mesh_quantum = Duration::from_secs(1);
    topic_score_params.invalid_message_deliveries_weight = -100.0; // INSTANT BAN
    topic_score_params.invalid_message_deliveries_decay = 0.99;

    let mut peer_score_params = gossipsub::PeerScoreParams::default();
    peer_score_params.topics.insert(
        gossipsub::IdentTopic::new("zero-protocol").hash(),
        topic_score_params,
    );
    peer_score_params.topic_score_cap = 50.0;
    peer_score_params.decay_interval = Duration::from_secs(1);
    peer_score_params.decay_to_zero = 0.1;
    peer_score_params.retain_score = Duration::from_secs(3600);

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn)
        .build()
        .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )
    .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

    gossipsub.with_peer_score(
        peer_score_params,
        gossipsub::PeerScoreThresholds {
            gossip_threshold: -10.0,
            publish_threshold: -50.0,
            graylist_threshold: -100.0,
            accept_px_threshold: 10.0,
            opportunistic_graft_threshold: 20.0,
        },
    );

    // 3. Configure Kademlia (DHT)
    let kademlia = kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));

    // 4. Configure mDNS (Local Discovery)
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

    // 5. Build Swarm
    let behaviour = ZeroBehaviour {
        gossipsub,
        kademlia,
        mdns,
    };

    let swarm = libp2p::Swarm::new(
        tcp_transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    Ok(swarm)
}
