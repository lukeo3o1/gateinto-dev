#![cfg(windows)]

#[allow(dead_code)]
mod fixture;

use std::ffi::OsString;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fixture::*;
use gateinto::job::Job;
use gateinto::proxy::{Config, LocalAuth, Proxy};
use tokio::io::AsyncWriteExt;

const CLOSE_WITHIN: Duration = Duration::from_secs(5);
const HELPER: &str = "a_helper_tunnels_through_the_proxy_given_on_its_command_line";

struct Setup {
    _ca: TestCa,
    upstream: UpstreamProxy,
    proxy: SocketAddr,
    target: SocketAddr,
}

impl Setup {
    async fn start(local_auth: LocalAuth, job: Option<Arc<Job>>) -> Self {
        let ca = TestCa::new();
        let upstream = UpstreamProxy::start(ca.server_config(PROXY_NAME), Behavior::Tunnel).await;
        let config = Config {
            local_auth,
            os_user_job: job,
            ..agent_config(upstream.addr, ca.roots(), PROXY_NAME)
        };
        let proxy = Proxy::bind(config).await.unwrap();
        let addr = proxy.local_addr();
        tokio::spawn(proxy.run());
        Self {
            _ca: ca,
            upstream,
            proxy: addr,
            target: echo_server().await,
        }
    }
}

async fn tunnel_as_this_process(proxy: SocketAddr, target: SocketAddr) {
    let (mut stream, response) = send(proxy, &connect_request(&target.to_string())).await;
    assert_eq!(response.status, 200, "{}", response.head);
    stream.write_all(b"as the same user").await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(
        read_to_end_within(&mut stream, CLOSE_WITHIN).await,
        b"as the same user"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_from_the_current_user_tunnels_without_credentials() {
    let setup = Setup::start(LocalAuth::OS_USER, None).await;
    tunnel_as_this_process(setup.proxy, setup.target).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_from_outside_the_job_is_forbidden() {
    let job = Arc::new(Job::new().unwrap());
    let setup = Setup::start(LocalAuth::OS_USER, Some(job)).await;
    let (_, response) = send(setup.proxy, &connect_request(&setup.target.to_string())).await;
    assert_eq!(response.status, 403, "{}", response.head);
    assert!(
        response.head.contains("Connection: close\r\n"),
        "{}",
        response.head
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_process_started_in_the_job_tunnels_without_credentials() {
    let job = Arc::new(Job::new().unwrap());
    let setup = Setup::start(LocalAuth::OS_USER, Some(job.clone())).await;
    let args: Vec<OsString> = [
        "--exact",
        HELPER,
        "--ignored",
        "--test-threads=1",
        &setup.proxy.to_string(),
        &setup.target.to_string(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let mut helper = job.spawn(&std::env::current_exe().unwrap(), &args).unwrap();
    let status = tokio::time::timeout(Duration::from_secs(60), helper.wait())
        .await
        .expect("the helper did not finish")
        .unwrap();
    assert!(status.success(), "{status}");
    let connect = format!("CONNECT {} HTTP/1.1", setup.target);
    let requests = setup.upstream.requests();
    assert!(
        requests.iter().any(|head| head.starts_with(&connect)),
        "the helper tunneled nothing: {requests:?}"
    );
}

#[ignore = "started inside a job by a_process_started_in_the_job_tunnels_without_credentials"]
#[tokio::test(flavor = "multi_thread")]
async fn a_helper_tunnels_through_the_proxy_given_on_its_command_line() {
    let addrs: Vec<SocketAddr> = std::env::args()
        .filter_map(|arg| arg.parse().ok())
        .collect();
    let [proxy, target] = addrs[..] else {
        return;
    };
    tunnel_as_this_process(proxy, target).await;
}
