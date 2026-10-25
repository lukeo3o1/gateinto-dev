#![cfg(windows)]

use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateinto::job::Job;

const SLEEPER: &str = "a_sleeper_starts_a_child_and_sleeps";
const CHILD: &str = "child";
const PARENT: &str = "parent";

fn sleeper_args(role: &str) -> Vec<OsString> {
    ["--exact", SLEEPER, "--ignored", "--test-threads=1", role]
        .into_iter()
        .map(OsString::from)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn killing_a_process_ends_its_children_and_leaves_the_job_empty() {
    let job = Arc::new(Job::new().unwrap());
    let mut process = job
        .spawn(&std::env::current_exe().unwrap(), &sleeper_args(PARENT))
        .unwrap();
    let started = Instant::now();
    while job.active_processes().unwrap() < 2 {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the sleeper did not start its child"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    process.kill().await.unwrap();
    assert_eq!(job.active_processes().unwrap(), 0);
}

fn started_sleeper(job: &Arc<Job>) -> gateinto::job::Process {
    let process = job
        .spawn(&std::env::current_exe().unwrap(), &sleeper_args(CHILD))
        .unwrap();
    let started = Instant::now();
    while job.active_processes().unwrap() < 1 {
        assert!(started.elapsed() < Duration::from_secs(30));
        std::thread::sleep(Duration::from_millis(20));
    }
    process
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_process_on_a_runtime_empties_the_job_without_blocking() {
    let job = Arc::new(Job::new().unwrap());
    drop(started_sleeper(&job));
    let dropped = Instant::now();
    while job.active_processes().unwrap() != 0 {
        assert!(dropped.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn dropping_a_process_outside_a_runtime_waits_until_the_job_is_empty() {
    let job = Arc::new(Job::new().unwrap());
    drop(started_sleeper(&job));
    assert_eq!(job.active_processes().unwrap(), 0);
}

#[ignore = "started inside a job by the tests above"]
#[test]
fn a_sleeper_starts_a_child_and_sleeps() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == PARENT) {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(sleeper_args(CHILD))
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        return;
    } else if !args.iter().any(|arg| arg == CHILD) {
        return;
    }
    std::thread::sleep(Duration::from_secs(120));
}
