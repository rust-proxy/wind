//! TUIC inbound server implementation with quiche

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::Duration,
};

use uuid::Uuid;

use crate::{
    utils::ConnectionOpts,
    Result,
};

/// TUIC server implementation using quiche
pub struct TuicheInbound {
    listen_addr: SocketAddr,
    users: HashMap<Uuid, Vec<u8>>,
    opts: ConnectionOpts,
}

impl TuicheInbound {
    /// Create a new TUIC server builder
    pub fn builder() -> TuicheInboundBuilder {
        TuicheInboundBuilder::new()
    }
}

/// Builder for TuicheInbound
pub struct TuicheInboundBuilder {
    listen_addr: Option<SocketAddr>,
    users: HashMap<Uuid, Vec<u8>>,
    max_idle_time: Duration,
    opts: ConnectionOpts,
}

impl TuicheInboundBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            listen_addr: None,
            users: HashMap::new(),
            max_idle_time: Duration::from_secs(30),
            opts: ConnectionOpts::default(),
        }
    }
    
    /// Set the listen address
    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }
    
    /// Add a user
    pub fn user(mut self, uuid: Uuid, password: String) -> Self {
        self.users.insert(uuid, password.into_bytes());
        self
    }
    
    /// Set maximum idle time
    pub fn max_idle_time(mut self, time: Duration) -> Self {
        self.max_idle_time = time;
        self
    }
    
    /// Set connection options
    pub fn connection_opts(mut self, opts: ConnectionOpts) -> Self {
        self.opts = opts;
        self
    }
    
    /// Build the server
    pub async fn build(self) -> Result<TuicheInbound> {
        let listen_addr = self.listen_addr.ok_or_else(|| eyre::eyre!("Listen address not set"))?;
        
        Ok(TuicheInbound {
            listen_addr,
            users: self.users,
            opts: self.opts,
        })
    }
}

impl Default for TuicheInboundBuilder {
    fn default() -> Self {
        Self::new()
    }
}