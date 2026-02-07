use crate::pow::{DEFAULT_DIFFICULTY, PoWMessage};
use libp2p::kad::{Quorum, Record};
use libp2p::{PeerId, Transport, gossipsub, kad, mdns, noise, swarm::NetworkBehaviour, tcp, yamux};
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use tokio::io;

/// Power mode for battery-aware networking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerMode {
    #[default]
    FullNode,
    LightClient,
    Standby,
}

impl PowerMode {
    pub fn heartbeat_interval(&self) -> Duration {
        match self {
            PowerMode::FullNode => Duration::from_secs(10),
            PowerMode::LightClient => Duration::from_secs(300),
            PowerMode::Standby => Duration::from_secs(600),
        }
    }

    pub fn mesh_n(&self) -> usize {
        match self {
            PowerMode::FullNode => 6,
            PowerMode::LightClient => 0,
            PowerMode::Standby => 0,
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ZeroEvent")]
pub struct ZeroBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: mdns::tokio::Behaviour,
}

#[derive(Debug)]
pub enum ZeroEvent {
    Gossipsub(gossipsub::Event),
    Kademlia(kad::Event),
    Mdns(mdns::Event),
}

impl From<gossipsub::Event> for ZeroEvent {
    fn from(event: gossipsub::Event) -> Self {
        ZeroEvent::Gossipsub(event)
    }
}

impl From<kad::Event> for ZeroEvent {
    fn from(event: kad::Event) -> Self {
        ZeroEvent::Kademlia(event)
    }
}

impl From<mdns::Event> for ZeroEvent {
    fn from(event: mdns::Event) -> Self {
        ZeroEvent::Mdns(event)
    }
}

/// Build a P2P swarm with default settings
pub async fn build_swarm(
    local_key: libp2p::identity::Keypair,
    bootstrap_peers: Option<Vec<(PeerId, libp2p::Multiaddr)>>,
) -> Result<libp2p::Swarm<ZeroBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(local_key.public());

    let tcp_config = tcp::Config::default().nodelay(true);
    let tcp_transport = tcp::tokio::Transport::new(tcp_config);
    let dns_transport = libp2p::dns::tokio::Transport::system(tcp_transport)?;

    let transport = dns_transport
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::Config::new(&local_key)?)
        .multiplex(yamux::Config::default())
        .boxed();

    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    let mut topic_score_params = gossipsub::TopicScoreParams::default();
    topic_score_params.topic_weight = 1.0;
    topic_score_params.time_in_mesh_weight = 0.01;
    topic_score_params.time_in_mesh_quantum = Duration::from_secs(1);
    topic_score_params.invalid_message_deliveries_weight = -100.0;
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
    )?;

    let kademlia = kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

    let behaviour = ZeroBehaviour {
        gossipsub,
        kademlia,
        mdns,
    };

    let mut swarm = libp2p::Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    if let Some(seeds) = bootstrap_peers {
        for peer in seeds {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer.0, peer.1.clone());
        }
    }

    Ok(swarm)
}

/// Build a swarm with power-aware configuration
pub async fn build_swarm_with_mode(
    local_key: libp2p::identity::Keypair,
    bootstrap_peers: Option<Vec<(PeerId, libp2p::Multiaddr)>>,
    mode: PowerMode,
) -> Result<libp2p::Swarm<ZeroBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(local_key.public());

    let tcp_config = tcp::Config::default().nodelay(true);
    let tcp_transport = tcp::tokio::Transport::new(tcp_config);
    let dns_transport = libp2p::dns::tokio::Transport::system(tcp_transport)?;

    let transport = dns_transport
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(noise::Config::new(&local_key)?)
        .multiplex(yamux::Config::default())
        .boxed();

    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    let mut gossipsub_config_builder = gossipsub::ConfigBuilder::default();
    gossipsub_config_builder
        .heartbeat_interval(mode.heartbeat_interval())
        .validation_mode(gossipsub::ValidationMode::Strict)
        .message_id_fn(message_id_fn);

    if mode != PowerMode::FullNode {
        gossipsub_config_builder
            .mesh_n(mode.mesh_n())
            .mesh_n_low(0)
            .mesh_n_high(mode.mesh_n().saturating_add(2));
    }

    let gossipsub_config = gossipsub_config_builder
        .build()
        .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )
    .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

    let kademlia = kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

    let behaviour = ZeroBehaviour {
        gossipsub,
        kademlia,
        mdns,
    };

    let mut swarm = libp2p::Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    if let Some(seeds) = bootstrap_peers {
        for peer in seeds {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer.0, peer.1.clone());
        }
    }

    Ok(swarm)
}

/// Verify incoming message has valid PoW
pub fn verify_incoming_message(data: &[u8]) -> Option<Vec<u8>> {
    let msg: PoWMessage = serde_json::from_slice(data).ok()?;
    if msg.verify(DEFAULT_DIFFICULTY) {
        Some(msg.payload)
    } else {
        None
    }
}

pub const MAILBOX_SLOTS: u8 = 50;

/// Derive DHT key for offline mailbox slot
pub fn derive_mailbox_key(peer_id: &PeerId, slot: u8) -> libp2p::kad::RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(peer_id.to_bytes());
    hasher.update(b"box");
    hasher.update(&[slot]);
    let result = hasher.finalize();
    libp2p::kad::RecordKey::new(&result)
}

/// Send message to recipient's DHT mailbox
pub fn send_offline_message(
    swarm: &mut libp2p::Swarm<ZeroBehaviour>,
    recipient: PeerId,
    message: Vec<u8>,
) -> Result<libp2p::kad::QueryId, libp2p::kad::store::Error> {
    let slot = rand::random::<u8>() % MAILBOX_SLOTS;
    let key = derive_mailbox_key(&recipient, slot);

    let record = Record {
        key,
        value: message,
        publisher: None,
        expires: None,
    };

    swarm
        .behaviour_mut()
        .kademlia
        .put_record(record, Quorum::One)
}

/// Check all mailbox slots for incoming messages
pub fn check_offline_inbox(swarm: &mut libp2p::Swarm<ZeroBehaviour>, local_peer_id: PeerId) {
    for slot in 0..MAILBOX_SLOTS {
        let key = derive_mailbox_key(&local_peer_id, slot);
        swarm.behaviour_mut().kademlia.get_record(key);
    }
}
