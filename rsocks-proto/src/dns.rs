use trust_dns_resolver::{
    TokioAsyncResolver,
    TokioHandle
};
use async_trait::async_trait;
use std::{
    sync::{Arc, Mutex, Condvar},
    error::Error,
    net::IpAddr,
    task::Poll
};
use futures::future;
use lazy_static::lazy_static;

lazy_static! {
    static ref GLOBAL_DNS_RESOLVER: TokioAsyncResolver = {
        let pair = Arc::new((Mutex::new(None::<TokioAsyncResolver>), Condvar::new()));
        let pair2 = pair.clone();

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("failed to launch Runtime");
            let resolver = {
                #[cfg(any(unix, windows))]
                {
                    // use the system resolver configuration
                    TokioAsyncResolver::from_system_conf(TokioHandle)
                }

                // For other operating systems, we can use one of the preconfigured definitions
                #[cfg(not(any(unix, windows)))]
                {
                    // Directly reference the config types
                    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

                    // Get a new resolver with the google nameservers as the upstream recursive resolvers
                    TokioAsyncResolver::new(ResolverConfig::google(), ResolverOpts::default(), runtime.handle().clone())
                }
            };
            let &(ref lock, ref cvar) = &*pair2;
            let mut started = lock.lock().unwrap();

            let resolver = resolver.expect("failed to create trust-dns-resolver");

            *started = Some(resolver);
            cvar.notify_one();
            drop(started);

            runtime.block_on(future::poll_fn(|_cx| Poll::<()>::Pending))
        });
        // Wait for the thread to start up.
        let &(ref lock, ref cvar) = &*pair;
        let mut resolver = lock.lock().unwrap();
        while resolver.is_none() {
            resolver = cvar.wait(resolver).unwrap();
        }

        // take the started resolver
        let resolver = std::mem::replace(&mut *resolver, None);

        // set the global resolver
        resolver.expect("resolver should not be none")
    };
}

#[async_trait]
pub(crate) trait Resolve {
    async fn look_ip(&self, addr: String) -> Result<IpAddr, Box<dyn Error + Send + Sync>>;
}

#[derive(Debug)]
pub struct DNSResolver;

#[async_trait]
impl Resolve for DNSResolver {
    async fn look_ip(&self, addr: String) -> Result<IpAddr, Box<dyn Error + Send + Sync>> {
        let addr1 = addr.clone();
        let result = GLOBAL_DNS_RESOLVER.lookup_ip(addr).await;
        match result {
            Ok(lookup) => {
                Ok(lookup.iter().next().unwrap())
            }
            Err(error) => {
                return Err(
                    Box::new(std::io::Error::new(std::io::ErrorKind::AddrNotAvailable,
                                                 format!("dns resolution error for {}: {}", addr1, error)))
                );
            }
        }
    }
}

impl DNSResolver {
    pub fn new() -> Self {
        Self {}
    }
}