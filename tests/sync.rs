//! End-to-end tests: real nodes talking over localhost TCP, with in-memory
//! clipboards standing in for the OS clipboard.

use clipshare::clipboard::MemoryClipboard;
use clipshare::crypto::{self, Secret};
use clipshare::service::{self, Options};
use std::time::Duration;
use tokio::time::{Instant, sleep};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct TestNode {
    clipboard: MemoryClipboard,
    port: u16,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn start(name: &str, secret: Secret, peers: Vec<u16>) -> TestNode {
    let clipboard = MemoryClipboard::default();
    let port = free_port();
    let opts = Options {
        device_id: hex::encode(rand::random::<[u8; 16]>()),
        device_name: name.into(),
        secret,
        port,
        peers: peers
            .into_iter()
            .map(|p| format!("127.0.0.1:{p}"))
            .collect(),
        discovery: false,
        poll_interval: Duration::from_millis(20),
    };
    let task = tokio::spawn(service::run(opts, clipboard.factory()));
    TestNode {
        clipboard,
        port,
        task,
    }
}

async fn wait_for(cb: &MemoryClipboard, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cb.get().as_deref() == Some(expected) {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "clipboard never became {expected:?}, it is {:?}",
        cb.get().map(|s| s.chars().take(80).collect::<String>())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn syncs_both_ways() {
    let secret = crypto::new_secret();
    let b = start("b", secret, vec![]);
    let a = start("a", secret, vec![b.port]);
    sleep(Duration::from_millis(300)).await;

    a.clipboard.set("hello from a");
    wait_for(&b.clipboard, "hello from a").await;

    b.clipboard.set("hello from b");
    wait_for(&a.clipboard, "hello from b").await;

    a.clipboard.set("and again");
    wait_for(&b.clipboard, "and again").await;

    // Nothing should bounce back and forth afterwards.
    sleep(Duration::from_millis(200)).await;
    assert_eq!(a.clipboard.get().as_deref(), Some("and again"));
    assert_eq!(b.clipboard.get().as_deref(), Some("and again"));
}

#[tokio::test(flavor = "multi_thread")]
async fn large_text_spans_many_frames() {
    let secret = crypto::new_secret();
    let b = start("b", secret, vec![]);
    let a = start("a", secret, vec![b.port]);
    sleep(Duration::from_millis(300)).await;

    let big: String = (0..300_000)
        .map(|i| char::from(b'a' + (i % 26) as u8))
        .collect::<String>()
        + "\"quotes\" ünïcødé 🎉";
    a.clipboard.set(&big);
    wait_for(&b.clipboard, &big).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn late_joiner_receives_latest_copy() {
    let secret = crypto::new_secret();
    let a = start("a", secret, vec![]);
    sleep(Duration::from_millis(200)).await;
    a.clipboard.set("copied while b was offline");
    sleep(Duration::from_millis(200)).await;

    let b = start("b", secret, vec![a.port]);
    wait_for(&b.clipboard, "copied while b was offline").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mutual_dialing_converges() {
    // Both sides dial each other; the duplicate connection must be dropped
    // consistently and sync must still work.
    let secret = crypto::new_secret();
    let pa = free_port();
    let pb = free_port();
    let mk = |name: &str, port, peer| {
        let clipboard = MemoryClipboard::default();
        let opts = Options {
            device_id: hex::encode(rand::random::<[u8; 16]>()),
            device_name: name.into(),
            secret,
            port,
            peers: vec![format!("127.0.0.1:{peer}")],
            discovery: false,
            poll_interval: Duration::from_millis(20),
        };
        TestNode {
            task: tokio::spawn(service::run(opts, clipboard.factory())),
            clipboard,
            port,
        }
    };
    let a = mk("a", pa, pb);
    let b = mk("b", pb, pa);
    sleep(Duration::from_millis(1500)).await;

    for i in 0..5 {
        let (src, dst) = if i % 2 == 0 { (&a, &b) } else { (&b, &a) };
        let text = format!("round {i}");
        src.clipboard.set(&text);
        wait_for(&dst.clipboard, &text).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn relays_across_three_devices() {
    // a <-> b <-> c, with no direct a-c connection.
    let secret = crypto::new_secret();
    let b = start("b", secret, vec![]);
    let a = start("a", secret, vec![b.port]);
    let c = start("c", secret, vec![b.port]);
    sleep(Duration::from_millis(400)).await;

    a.clipboard.set("from a");
    wait_for(&c.clipboard, "from a").await;
    c.clipboard.set("from c");
    wait_for(&a.clipboard, "from c").await;
    wait_for(&b.clipboard, "from c").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_pairing_code_cannot_connect() {
    let b = start("b", crypto::new_secret(), vec![]);
    let a = start("a", crypto::new_secret(), vec![b.port]);
    sleep(Duration::from_millis(300)).await;

    a.clipboard.set("secret stuff");
    sleep(Duration::from_millis(800)).await;
    assert_eq!(b.clipboard.get(), None);
}
