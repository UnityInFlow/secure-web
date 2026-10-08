//! Per-hop HTTP client pinned to the addresses the URL guard validated (threat T5/T6).
//!
//! reqwest's DNS resolver is replaced by [`PinnedResolver`], which answers **only** the validated
//! host with **only** the validated addresses and fails every other lookup. There is no second
//! DNS lookup between check and connect, so DNS rebinding cannot swap in another address. IP
//! literal hosts never reach the resolver at all. Proxies are disabled (a proxy would connect on
//! our behalf to wherever it likes), and redirects are never followed by the client.

use std::net::SocketAddr;
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use secure_web_security::ssrf::ValidatedTarget;

use crate::error::FetchError;
use crate::limits::FetchLimits;

/// Resolver that knows exactly one host name and its validated addresses.
struct PinnedResolver {
    host: String,
    addrs: Vec<SocketAddr>,
}

impl Resolve for PinnedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let answer = if name
            .as_str()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(self.host.trim_end_matches('.'))
        {
            Ok(self.addrs.clone())
        } else {
            Err(())
        };
        Box::pin(async move {
            match answer {
                Ok(addrs) => Ok(Box::new(addrs.into_iter()) as Addrs),
                Err(()) => Err("secure-web: lookup outside the validated target refused".into()),
            }
        })
    }
}

/// A client that can reach only `target`'s validated addresses.
pub(crate) fn client_for(
    target: &ValidatedTarget,
    limits: &FetchLimits,
    user_agent: &str,
) -> Result<reqwest::Client, FetchError> {
    let resolver = PinnedResolver {
        host: target.host().to_owned(),
        addrs: target
            .addrs()
            .iter()
            .map(|ip| SocketAddr::new(*ip, target.port()))
            .collect(),
    };
    reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .referer(false)
        .dns_resolver(Arc::new(resolver))
        .connect_timeout(limits.connect_timeout)
        .timeout(limits.request_timeout)
        .pool_max_idle_per_host(0)
        .user_agent(user_agent)
        .build()
        .map_err(|_| FetchError::Client)
}
