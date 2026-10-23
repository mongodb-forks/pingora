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

//! S2N server specific implementation

use crate::listeners::tls::Acceptor;
use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::{AutoFlushableStream, TlsStream};
use crate::protocols::TlsRef;
use crate::protocols::IO;
use pingora_error::ErrorType::TLSHandshakeFailure;
use pingora_error::{Error, Result};

pub async fn handshake<S: IO>(acceptor: &Acceptor, stream: S) -> Result<TlsStream<S>> {
    // Wrap incoming stream in an auto flushable stream with auto flush enabled because
    // s2n-tls doesn't invoke flush after writing to the connection. This would result in
    // the handshake hanging and timing on streams with write buffering.
    let auto_flushable_stream = AutoFlushableStream::new(stream, true);
    let mut s2n_stream = acceptor
        .acceptor
        .accept(auto_flushable_stream)
        .await
        .map_err(|e| {
            let context = format!("TLS accept() failed: {e}");
            Error::explain(TLSHandshakeFailure, context)
        })?;

    // Disable auto-flush to not interfere with write buffering going forward.
    s2n_stream.get_mut().set_auto_flush(false);

    Ok(TlsStream::from_s2n_stream(s2n_stream))
}

pub async fn handshake_with_callback<S: IO>(
    acceptor: &Acceptor,
    stream: S,
    callbacks: &TlsAcceptCallbacks,
) -> Result<TlsStream<S>> {
    let mut tls_stream = handshake(acceptor, stream).await?;
    {
        let tls_ref: &TlsRef = AsRef::<TlsRef>::as_ref(&*tls_stream);
        if let Some(extension) = callbacks.handshake_complete_callback(tls_ref).await {
            if let Some(digest_mut) = tls_stream.ssl_digest_mut() {
                digest_mut.extension.set(extension);
            }
        }
    }
    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use crate::{
        listeners::{
            tls::{Acceptor, TlsSettings},
            TlsAccept, TlsAcceptCallbacks,
        },
        protocols::tls::TlsRef,
    };
    use async_trait::async_trait;
    use pingora_s2n::{Config, TlsConnector};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, DuplexStream};

    struct Sni(String);
    struct Callback;
    #[async_trait]
    impl TlsAccept for Callback {
        async fn handshake_complete_callback(
            &self,
            tls_ref: &TlsRef,
        ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
            Some(Arc::new(Sni(tls_ref.server_name().unwrap().to_owned())))
        }
    }

    async fn client_task(client: DuplexStream) {
        let mut builder = Config::builder();
        // SAFETY: we are in a test environment so disabling X509 authentication is ok
        unsafe {
            builder.disable_x509_verification().unwrap();
        }
        let connector = TlsConnector::new(builder.build().unwrap());
        let mut stream = connector.connect("pingora.org", client).await.unwrap();
        let mut buf = [0; 1];
        let _ = stream.read(&mut buf).await;
    }

    fn acceptor(callbacks: Option<TlsAcceptCallbacks>) -> Acceptor {
        let mut settings = match callbacks {
            None => TlsSettings::new(),
            Some(cb) => TlsSettings::with_callbacks(cb).unwrap(),
        };
        settings.set_cert(
            &format!("{}/tests/keys/server.crt", env!("CARGO_MANIFEST_DIR")),
            &format!("{}/tests/keys/key.pem", env!("CARGO_MANIFEST_DIR")),
        );
        settings.build()
    }

    #[tokio::test]
    async fn test_handshake_complete_callback() {
        let cb: TlsAcceptCallbacks = Box::new(Callback);
        let acceptor = acceptor(Some(cb));
        let (client, server) = tokio::io::duplex(1024);

        tokio::spawn(client_task(client));
        let stream = acceptor.tls_handshake(server).await.unwrap();

        let ssl_digest = stream.ssl_digest().unwrap();
        let sni = ssl_digest.extension.get::<Sni>().unwrap();
        assert_eq!(sni.0, "pingora.org");
    }
}
