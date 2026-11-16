// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod client;
pub mod server;
mod stream;

use crate::protocols::ALPN;
use crate::utils::tls::X509Pem;
use pingora_error::ErrorType::InternalError;
use pingora_error::OrErr;
use pingora_s2n::{
    Config, ConfigBuilder, Connection, ConnectionBuilder, IgnoreVerifyHostnameCallback, Mode,
    Psk as S2NPsk, PskHmac, S2NError, S2NPolicy,
};
use s2n_tls::enums::{ClientAuthType, SerializationVersion};
use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};
pub use stream::*;

pub type CaType = X509Pem;

pub type PskType = PskConfig;

#[derive(Debug)]
pub struct PskConfig {
    pub keys: Vec<Psk>,
}

impl PskConfig {
    pub fn new(keys: Vec<Psk>) -> Self {
        Self { keys }
    }
}

impl Hash for PskConfig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for psk in self.keys.iter() {
            psk.identity.hash(state);
            psk.secret.hash(state);
        }
    }
}

#[derive(Debug)]
pub struct Psk {
    pub identity: Vec<u8>,
    pub secret: Vec<u8>,
    pub hmac: PskHmac,
}

impl Psk {
    pub fn new(identity: String, secret: Vec<u8>, hmac: PskHmac) -> Self {
        Self {
            identity: identity.into_bytes(),
            secret,
            hmac,
        }
    }
}

pub type TlsRef = pingora_s2n::Connection;

/// Config settings that are fixed for a given listener, cannot be set per-connection
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ServerTlsOptions {
    pub max_blinding_delay: Option<u32>,
    pub client_auth_type: Option<ClientAuthType>,
    pub alpn: Option<ALPN>,
    pub verify_client_hostname: bool,
    pub allow_serialization: bool,
}

impl ServerTlsOptions {
    /// Returns a `ConfigBuilder` using the options set in `ServerTlsOptions`.
    pub fn config_builder(&self) -> pingora_error::Result<ConfigBuilder> {
        let mut builder = Config::builder();
        if let Some(max_blinding_delay) = self.max_blinding_delay {
            builder
                .set_max_blinding_delay(max_blinding_delay)
                .or_err(InternalError, "failed to set max blinding delay")?;
        }

        builder
            .set_client_auth_type(self.client_auth_type.unwrap_or(ClientAuthType::Optional))
            .or_err(InternalError, "failed to set client auth type")?;

        if let Some(alpn) = &self.alpn {
            builder
                .set_application_protocol_preference(alpn.to_wire_protocols())
                .or_err(InternalError, "failed to set ALPN")?;
        }

        if !self.verify_client_hostname {
            builder
                .set_verify_host_callback(IgnoreVerifyHostnameCallback::new())
                .or_err(InternalError, "failed to set verify host callback")?;
        }

        if self.allow_serialization {
            builder
                .set_serialization_version(SerializationVersion::V1)
                .or_err(InternalError, "could not init serialization")?;
        }
        Ok(builder)
    }
}

/// The closure here should be cheap, is called on every connection
/// Should not build a config inside the closure, but instead return a pre-built one
#[derive(Clone)]
pub struct ConfigProvider(Arc<dyn Fn() -> Config + Send + Sync>);

impl ConfigProvider {
    pub fn new<F: Fn() -> Config + Send + Sync + 'static>(f: F) -> Self {
        Self(Arc::new(f))
    }

    pub fn fixed(config: Config) -> Self {
        Self::new(move || config.clone())
    }
    pub fn get(&self) -> Config {
        self.0()
    }
}

impl std::fmt::Debug for ConfigProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ConfigProvider")
    }
}

/// Custom s2n-tls connection builder. The s2n-tls-tokio crate doesn't expose
/// a higher level api to configure private shared keys on a TLS connection.
///
/// This builder will create a new connection and configure it with the appropriate
/// psk configurations based on the provided private shared keys.
/// ```
#[derive(Debug, Clone)]
pub struct S2NConnectionBuilder {
    pub config_provider: ConfigProvider,
    pub psk_config: Option<Arc<PskConfig>>,
    pub security_policy: Option<S2NPolicy>,
    pub allow_serialization: bool,
}

impl ConnectionBuilder for S2NConnectionBuilder {
    type Output = Connection;
    fn build_connection(&self, mode: Mode) -> std::result::Result<Self::Output, S2NError> {
        let mut conn = Connection::new(mode);
        conn.set_config(self.config_provider.get())?;

        if let Some(psk_config) = &self.psk_config {
            for psk in psk_config.keys.iter() {
                let mut psk_builder = S2NPsk::builder()?;
                psk_builder.set_identity(&psk.identity)?;
                psk_builder.set_hmac(PskHmac::SHA256)?;
                psk_builder.set_secret(&psk.secret)?;
                conn.append_psk(&psk_builder.build()?)?;
            }
        }

        if let Some(policy) = &self.security_policy {
            conn.set_security_policy(policy)?;
        }

        // If serialization is enabled, then receive buffering
        // should be turned off since this data isn't included
        // in the serialization.
        if self.allow_serialization {
            conn.set_receive_buffering(false)?;
        }

        Ok(conn)
    }
}
