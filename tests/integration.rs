//! End-to-end behaviour against a real PostgreSQL. Run through `scripts/integration.sh`.

mod common;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;

use common::{
    Client, Lokaj, admin, bind, execute, flush, msg, parse, pki, query, sync, tenant, terminate,
};
use lokaj::protocol;

async fn backend_pid(client: &mut Client) -> String {
    client.query_one("select pg_backend_pid()").await
}

#[tokio::test]
async fn tls_is_required() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let mut client = Client::plain(lokaj.addr).await;
    client
        .send_startup(&[("user", "x"), ("database", "x")])
        .await;
    assert_eq!(client.expect_fatal().await.code, "28000");
}

#[tokio::test]
async fn server_connections_use_verified_tls() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    assert_eq!(
        a.query_one("select ssl::text from pg_stat_ssl where pid = pg_backend_pid()")
            .await,
        "true"
    );
    // The server's certificate does not chain to this CA.
    let untrusted = Lokaj::with(|c| c.server.ca = pki().dir.join("ca.crt")).await;
    let mut client = untrusted.client().await;
    let error = client
        .login(&alice.params(), &alice.password)
        .await
        .unwrap_err();
    assert_eq!(error.code, "08006");
    assert_eq!(
        untrusted
            .metric("lokaj_server_connect_errors_total{reason=\"tls\"}")
            .await,
        1.0
    );
}

#[tokio::test]
async fn an_idle_connection_the_server_closed_is_not_reused() {
    require_pg!();
    let lokaj = Lokaj::with(|c| c.pool.max_size = 1).await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    let pid = backend_pid(&mut a).await;
    admin()
        .await
        .query(&format!("select pg_terminate_backend({pid}, 5000)"))
        .await
        .unwrap();
    assert_ne!(backend_pid(&mut a).await, pid);
    assert_eq!(
        lokaj
            .metric("lokaj_server_recycles_total{reason=\"server_closed\"}")
            .await,
        1.0
    );
}

#[tokio::test]
async fn the_reaper_closes_idle_connections_the_server_closed() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    let pid = backend_pid(&mut a).await;
    admin()
        .await
        .query(&format!("select pg_terminate_backend({pid}, 5000)"))
        .await
        .unwrap();
    // No client asks for the connection; the reaper's next pass finds it.
    let sample = "lokaj_server_recycles_total{reason=\"server_closed\"}";
    for _ in 0..30 {
        if lokaj.metric(sample).await == 1.0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(lokaj.metric(sample).await, 1.0);
}

#[tokio::test]
async fn passwords_are_verified_by_the_server() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let bob = tenant().await;

    let mut client = lokaj.client().await;
    let error = client.login(&alice.params(), "wrong").await.unwrap_err();
    assert_eq!(error.code, "28P01");

    // Bob's valid password does not work for Alice, before or after Alice is cached.
    let mut client = lokaj.client().await;
    assert_eq!(
        client
            .login(&alice.params(), &bob.password)
            .await
            .unwrap_err()
            .code,
        "28P01"
    );
    let mut client = lokaj.login(&alice).await;
    assert_eq!(
        client.params.get("session_authorization"),
        Some(&alice.user)
    );
    assert_eq!(
        client.params.get("application_name").map(String::as_str),
        Some("test")
    );
    assert!(client.params.contains_key("server_version"));
    assert!(client.key.is_some());
    assert_eq!(client.query_one("select current_user").await, alice.user);
    let mut client = lokaj.client().await;
    assert_eq!(
        client
            .login(&alice.params(), &bob.password)
            .await
            .unwrap_err()
            .code,
        "28P01"
    );
    // Alice's password only works for her own database.
    let mut params = alice.params();
    params[1].1 = &bob.database;
    let mut client = lokaj.client().await;
    assert_eq!(
        client
            .login(&params, &alice.password)
            .await
            .unwrap_err()
            .code,
        "42501"
    );

    assert_eq!(
        lokaj
            .metric("lokaj_credential_cache_total{result=\"miss\"}")
            .await,
        1.0
    );
    lokaj.login(&alice).await;
    assert_eq!(
        lokaj
            .metric("lokaj_credential_cache_total{result=\"hit\"}")
            .await,
        1.0
    );
}

#[tokio::test]
async fn failed_logins_lock_out_the_failing_source() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    lokaj.login(&alice).await;
    let attacker: IpAddr = "127.0.0.2".parse().unwrap();
    // Once locked, the source learns nothing, not even from the right password.
    for password in ["guess"; 6].into_iter().chain([alice.password.as_str()]) {
        let mut client = lokaj.client_from(attacker).await;
        assert_eq!(
            client
                .login(&alice.params(), password)
                .await
                .unwrap_err()
                .code,
            "28P01"
        );
    }
    assert_eq!(
        lokaj
            .metric("lokaj_auth_failures_total{reason=\"rejected\"}")
            .await,
        5.0
    );
    assert_eq!(
        lokaj
            .metric("lokaj_auth_failures_total{reason=\"rate_limited\"}")
            .await,
        2.0
    );
    // Other sources keep logging in with the verified password.
    lokaj.login(&alice).await;
}

#[tokio::test]
async fn a_refusal_before_authentication_is_not_a_wrong_password() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut admin = admin().await;
    admin
        .query("do $$ begin create role refused; exception when duplicate_object then null; end $$")
        .await
        .unwrap();
    admin
        .query(&format!("grant refused to \"{}\"", alice.user))
        .await
        .unwrap();
    // More refusals than auth.max_failures, and none of them locks the client out.
    for _ in 0..6 {
        let mut client = lokaj.client().await;
        let error = client
            .login(&alice.params(), &alice.password)
            .await
            .unwrap_err();
        assert_eq!(error.code, "28000");
    }
    assert_eq!(
        lokaj
            .metric("lokaj_server_connect_errors_total{reason=\"refused\"}")
            .await,
        6.0
    );
    assert_eq!(
        lokaj
            .metric("lokaj_auth_failures_total{reason=\"rejected\"}")
            .await,
        0.0
    );
    admin
        .query(&format!("revoke refused from \"{}\"", alice.user))
        .await
        .unwrap();
    lokaj.login(&alice).await;
}

#[tokio::test]
async fn a_server_asking_for_md5_gets_a_clear_refusal() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut admin = admin().await;
    admin
        .query("do $$ begin create role md5; exception when duplicate_object then null; end $$")
        .await
        .unwrap();
    admin
        .query(&format!("grant md5 to \"{}\"", alice.user))
        .await
        .unwrap();
    // An MD5 verifier, as roles created before SCRAM have; with a SCRAM one, md5 means SCRAM.
    admin
        .query("set password_encryption = 'md5'")
        .await
        .unwrap();
    admin
        .query(&format!(
            "alter role \"{}\" password '{}'",
            alice.user, alice.password
        ))
        .await
        .unwrap();
    let mut client = lokaj.client().await;
    let error = client
        .login(&alice.params(), &alice.password)
        .await
        .unwrap_err();
    assert_eq!(error.code, "28000", "{}", error.message);
    assert!(error.message.contains("SCRAM-SHA-256"), "{}", error.message);
    assert_eq!(
        lokaj
            .metric("lokaj_server_connect_errors_total{reason=\"unsupported_auth\"}")
            .await,
        1.0
    );
}

#[tokio::test]
async fn a_failed_tls_handshake_is_counted() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let mut client = Client::plain(lokaj.addr).await;
    let mut request = 8i32.to_be_bytes().to_vec();
    request.extend_from_slice(&protocol::SSL_REQUEST_CODE.to_be_bytes());
    client.send(&request).await;
    client.send(&[0x16; 64]).await;
    let sample = "lokaj_client_rejects_total{reason=\"tls_handshake\"}";
    for _ in 0..30 {
        if lokaj.metric(sample).await == 1.0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(lokaj.metric(sample).await, 1.0);
}

#[tokio::test]
async fn simple_and_extended_queries() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut client = lokaj.login(&alice).await;
    assert_eq!(
        client.query("select 1; select 'a', null").await.unwrap(),
        vec![vec![Some("1".into())], vec![Some("a".into()), None]]
    );
    assert_eq!(
        client
            .extended("select $1::int + $2::int", &["40", "2"])
            .await
            .unwrap(),
        vec![vec![Some("42".into())]]
    );
    let error = client.extended("select 1/0", &[]).await.unwrap_err();
    assert_eq!(error.code, "22012");
    assert_eq!(
        client.query_one("select 'still usable'").await,
        "still usable"
    );
}

#[tokio::test]
async fn pipelined_queries_are_answered_in_order() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut client = lokaj.login(&alice).await;
    let mut out = query("select 1");
    out.extend(query("select 2"));
    out.extend(parse("", "select $1::text"));
    out.extend(bind("", "", &["3"]));
    out.extend(execute());
    out.extend(sync());
    client.send(&out).await;
    for expected in ["1", "2", "3"] {
        let (rows, error, status) = client.results().await;
        assert!(error.is_none());
        assert_eq!(rows[0][0].as_deref(), Some(expected));
        assert_eq!(status, b'I');
    }
}

async fn assert_rejected(lokaj: &Lokaj, alice: &common::Tenant, messages: Vec<u8>, code: &str) {
    let mut client = lokaj.login(alice).await;
    client.send(&messages).await;
    assert_eq!(client.expect_fatal().await.code, code);
}

#[tokio::test]
async fn unsupported_messages_end_the_session() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut named = parse("s1", "select 1");
    named.extend(sync());
    assert_rejected(&lokaj, &alice, named, "0A000").await;
    let mut unprepared = bind("", "", &[]);
    unprepared.extend(execute());
    unprepared.extend(sync());
    assert_rejected(&lokaj, &alice, unprepared, "26000").await;
    assert_rejected(&lokaj, &alice, msg(b'F', &[0, 0, 0, 1]), "0A000").await;
    assert_rejected(&lokaj, &alice, query("set search_path = public"), "0A000").await;
    assert_rejected(&lokaj, &alice, query("select 1; discard all"), "0A000").await;
    assert_rejected(&lokaj, &alice, query("copy (select 1) to stdout"), "0A000").await;
    assert_rejected(&lokaj, &alice, msg(b'Q', b"no terminator"), "08P01").await;

    let mut client = lokaj.login(&alice).await;
    client.query("begin").await.unwrap();
    client
        .query("set local statement_timeout = 1000")
        .await
        .unwrap();
    client
        .query("set transaction isolation level repeatable read")
        .await
        .unwrap();
    client.query("rollback").await.unwrap();
}

#[tokio::test]
async fn startup_parameters_are_checked() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    for extra in [
        ("options", "-c search_path=x"),
        ("replication", "database"),
        ("client_encoding", "LATIN1"),
        ("statement_timeout", "1s"),
    ] {
        let mut params = alice.params();
        params.retain(|(name, _)| *name != extra.0);
        params.push(extra);
        let mut client = lokaj.client().await;
        client.send_startup(&params).await;
        assert!(
            client.expect_fatal().await.code.starts_with(['0', '2']),
            "{extra:?}"
        );
    }

    // Longer names would be truncated by the server into another identity.
    let long = "x".repeat(64);
    for name in ["user", "database"] {
        let mut params = alice.params();
        params.retain(|(n, _)| *n != name);
        params.push((name, &long));
        let mut client = lokaj.client().await;
        client.send_startup(&params).await;
        assert_eq!(client.expect_fatal().await.code, "42622", "{name}");
    }

    // Protocol 3.2 and `_pq_` options are negotiated down.
    let mut client = lokaj.client().await;
    let mut packet = Vec::new();
    packet.extend_from_slice(&((3 << 16) | 2i32).to_be_bytes());
    for (name, value) in alice.params().into_iter().chain([("_pq_.test", "1")]) {
        packet.extend_from_slice(name.as_bytes());
        packet.push(0);
        packet.extend_from_slice(value.as_bytes());
        packet.push(0);
    }
    packet.push(0);
    let mut framed = (packet.len() as i32 + 4).to_be_bytes().to_vec();
    framed.extend(packet);
    client.send(&framed).await;
    let (tag, body) = client.recv().await;
    assert_eq!(tag, b'v');
    assert_eq!(&body[..8], &[0, 3, 0, 0, 0, 0, 0, 1]);
    client.authenticate(&alice.password).await.unwrap();
}

#[tokio::test]
async fn session_options_from_startup_apply_on_the_server() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut params = alice.params();
    params.push(("statement_timeout", "200"));
    let mut limited = lokaj.client().await;
    limited.login(&params, &alice.password).await.unwrap();
    assert_eq!(
        limited.query("select pg_sleep(2)").await.unwrap_err().code,
        "57014"
    );
    let mut unlimited = lokaj.login(&alice).await;
    unlimited.query("select pg_sleep(0.5)").await.unwrap();
}

#[tokio::test]
async fn one_database_gets_a_bounded_number_of_option_variants() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut clients = vec![lokaj.login(&alice).await];
    for (timeout, expected) in [("100", None), ("200", Some("0A000"))] {
        let mut params = alice.params();
        params.push(("statement_timeout", timeout));
        let mut client = lokaj.client().await;
        let result = client.login(&params, &alice.password).await;
        assert_eq!(
            result.err().map(|e| e.code),
            expected.map(String::from),
            "{timeout}"
        );
        clients.push(client);
    }
    // Existing variants stay usable.
    lokaj.login(&alice).await.query("select 1").await.unwrap();
}

#[tokio::test]
async fn server_connections_are_shared_between_transactions() {
    require_pg!();
    let lokaj = Lokaj::with(|c| c.pool.max_size = 1).await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    let mut b = lokaj.login(&alice).await;
    let pid = backend_pid(&mut a).await;
    assert_eq!(backend_pid(&mut b).await, pid);
    assert_eq!(backend_pid(&mut a).await, pid);
    assert_eq!(lokaj.metric("lokaj_server_connects_total").await, 1.0);
}

#[tokio::test]
async fn a_transaction_keeps_its_server_connection() {
    require_pg!();
    let lokaj = Lokaj::with(|c| {
        c.pool.max_size = 1;
        c.pool.wait_timeout = Duration::from_millis(300);
    })
    .await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    a.query("begin isolation level repeatable read")
        .await
        .unwrap();
    let pid = backend_pid(&mut a).await;
    a.query("savepoint s").await.unwrap();
    a.query("select 1/0").await.unwrap_err();
    a.query("rollback to savepoint s").await.unwrap();
    assert_eq!(backend_pid(&mut a).await, pid);

    let mut b = lokaj.login(&alice).await;
    b.send(&query("select 1")).await;
    assert_eq!(b.expect_fatal().await.code, "53300");

    a.query("commit").await.unwrap();
    let mut c = lokaj.login(&alice).await;
    assert_eq!(backend_pid(&mut c).await, pid);
}

#[tokio::test]
async fn a_client_idle_in_a_transaction_gives_up_its_connection() {
    require_pg!();
    let lokaj = Lokaj::with(|c| {
        c.pool.max_size = 1;
        c.client.idle_transaction_timeout = Duration::from_millis(300);
    })
    .await;
    let alice = tenant().await;
    let mut idle = lokaj.login(&alice).await;
    idle.query("select 1").await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    // Outside a transaction the client holds nothing and may idle.
    idle.query("begin").await.unwrap();
    let mut other = lokaj.login(&alice).await;
    other.send(&query("select 1")).await;
    assert_eq!(idle.expect_fatal().await.code, "25P03");
    assert_eq!(other.results().await.0, vec![vec![Some("1".into())]]);

    // An unfinished extended-protocol batch holds the connection too.
    let mut unsynced = lokaj.login(&alice).await;
    unsynced.send(&parse("", "select 1")).await;
    assert_eq!(unsynced.expect_fatal().await.code, "25P03");
    other.query("select 1").await.unwrap();
    assert_eq!(
        lokaj
            .metric("lokaj_session_errors_total{reason=\"idle_in_transaction\"}")
            .await,
        2.0
    );
}

#[tokio::test]
async fn an_execute_the_server_still_runs_is_not_idle() {
    require_pg!();
    let lokaj = Lokaj::with(|c| {
        c.client.idle_transaction_timeout = Duration::from_millis(300);
    })
    .await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    // node-pg's `rows` option sends Execute and Flush, and Sync only after the last page.
    let mut out = parse("", "select pg_sleep(0.6)::text");
    out.extend(bind("", "", &[]));
    out.extend(execute());
    out.extend(flush());
    a.send(&out).await;
    loop {
        let (tag, _) = a.recv().await;
        assert_ne!(tag, b'E', "the running Execute was treated as idle");
        if tag == b'C' {
            break;
        }
    }
    a.send(&sync()).await;
    assert_eq!(a.results().await.1, None);
    a.query("select 1").await.unwrap();
}

#[tokio::test]
async fn sessions_refused_a_connection_are_counted() {
    require_pg!();
    let lokaj = Lokaj::with(|c| {
        c.pool.max_size = 1;
        c.pool.max_waiters = 0;
    })
    .await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    a.query("begin").await.unwrap();
    let waits = || async {
        let mut total = 0.0;
        for source in ["idle", "released", "new"] {
            let sample = format!("lokaj_pool_wait_seconds_count{{source=\"{source}\"}}");
            total += lokaj.metric(&sample).await;
        }
        total
    };
    let before = waits().await;
    assert!(before > 0.0);
    let mut b = lokaj.login(&alice).await;
    b.send(&query("select 1")).await;
    assert_eq!(b.expect_fatal().await.code, "53300");
    assert_eq!(
        lokaj
            .metric("lokaj_session_errors_total{reason=\"too_many_waiters\"}")
            .await,
        1.0
    );
    // Only waits that got a connection are in the histogram.
    assert_eq!(waits().await, before);
}

#[tokio::test]
async fn a_client_that_stops_reading_gives_up_its_connection() {
    require_pg!();
    let lokaj = Lokaj::with(|c| {
        c.pool.max_size = 1;
        c.client.idle_transaction_timeout = Duration::from_millis(500);
    })
    .await;
    let alice = tenant().await;
    let mut stalled = lokaj.login(&alice).await;
    // Far more than the socket buffers and lokaj's output buffer hold; never read.
    stalled
        .send(&query(
            "select repeat('x', 1000000) from generate_series(1, 50)",
        ))
        .await;
    let mut other = lokaj.login(&alice).await;
    assert_eq!(other.query_one("select 1").await, "1");
    assert_eq!(
        lokaj
            .metric("lokaj_server_recycles_total{reason=\"client_stalled\"}")
            .await,
        1.0
    );
}

#[tokio::test]
async fn sessions_are_read_only_on_a_writer_too() {
    require_pg!();
    // The test server is a primary, like a reader endpoint that fell back to the writer.
    let lokaj = Lokaj::with(|c| c.pool.max_size = 1).await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    let error = a
        .query("create temp table t as select 'secret of a' s")
        .await
        .unwrap_err();
    assert_eq!(error.code, "25006");
    let mut b = lokaj.login(&alice).await;
    assert_eq!(b.query("select s from t").await.unwrap_err().code, "42P01");
}

#[tokio::test]
async fn unnamed_statements_do_not_leak_between_clients() {
    require_pg!();
    let lokaj = Lokaj::with(|c| c.pool.max_size = 1).await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    let mut out = parse("", "select 'secret of a'");
    out.extend(sync());
    a.send(&out).await;
    a.results().await;
    let mut b = lokaj.login(&alice).await;
    let mut out = bind("", "", &[]);
    out.extend(execute());
    out.extend(sync());
    b.send(&out).await;
    assert_eq!(b.expect_fatal().await.code, "26000");
}

#[tokio::test]
async fn cancel_requests_reach_only_the_running_query() {
    require_pg!();
    let lokaj = Lokaj::with(|c| c.pool.max_size = 1).await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    let pid = backend_pid(&mut a).await;
    let (process_id, secret) = a.key.clone().unwrap();
    a.send(&query("select pg_sleep(30)")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A wrong secret is ignored.
    let mut forged = secret.clone();
    forged[0] ^= 1;
    let mut cancel = Client::tls(lokaj.addr).await;
    cancel
        .send(&protocol::cancel_request(process_id, &forged))
        .await;
    cancel.expect_closed().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        lokaj
            .metric("lokaj_cancels_total{result=\"unknown\"}")
            .await,
        1.0
    );

    let mut cancel = Client::plain(lokaj.addr).await;
    cancel
        .send(&protocol::cancel_request(process_id, &secret))
        .await;
    cancel.expect_closed().await;
    let (_, error, _) = a.results().await;
    assert_eq!(error.unwrap().code, "57014");
    // The cancelled connection is not reused.
    assert_ne!(backend_pid(&mut a).await, pid);
    assert_eq!(
        lokaj
            .metric("lokaj_server_recycles_total{reason=\"cancelled\"}")
            .await,
        1.0
    );
}

async fn active_queries(user: &str) -> usize {
    let mut admin = admin().await;
    let sql = format!(
        "select count(*) from pg_stat_activity where usename = '{user}' and state = 'active' and query like '%pg_sleep%'"
    );
    admin.query_one(&sql).await.parse().unwrap()
}

#[tokio::test]
async fn a_client_leaving_mid_query_cancels_it() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    a.send(&query("select pg_sleep(30)")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(active_queries(&alice.user).await, 1);
    drop(a);
    for _ in 0..30 {
        if active_queries(&alice.user).await == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the abandoned query is still running");
}

#[tokio::test]
async fn terminate_inside_a_transaction_discards_the_connection() {
    require_pg!();
    let lokaj = Lokaj::with(|c| c.pool.max_size = 1).await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    a.query("begin").await.unwrap();
    let pid = backend_pid(&mut a).await;
    a.send(&terminate()).await;
    a.expect_closed().await;
    let mut b = lokaj.login(&alice).await;
    assert_ne!(backend_pid(&mut b).await, pid);
    assert_eq!(
        b.query_one("select now() = statement_timestamp()").await,
        "t"
    );
}

#[tokio::test]
async fn changed_session_parameters_retire_the_connection() {
    require_pg!();
    let lokaj = Lokaj::with(|c| c.pool.max_size = 1).await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    let original = a.query_one("show timezone").await;
    let pid = backend_pid(&mut a).await;
    // set_config() is not caught by the lexical guard; the reported parameter change is.
    a.query("select set_config('TimeZone', 'Asia/Tokyo', false)")
        .await
        .unwrap();
    assert_eq!(
        a.params.get("TimeZone").map(String::as_str),
        Some("Asia/Tokyo")
    );
    let mut b = lokaj.login(&alice).await;
    assert_eq!(b.query_one("show timezone").await, original);
    assert_ne!(backend_pid(&mut b).await, pid);
    assert_eq!(
        lokaj
            .metric("lokaj_server_recycles_total{reason=\"dirty\"}")
            .await,
        1.0
    );
}

#[tokio::test]
async fn changing_how_the_guard_reads_sql_retires_the_connection() {
    require_pg!();
    let lokaj = Lokaj::with(|c| c.pool.max_size = 1).await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    let original = a.query_one("show work_mem").await;
    let pid = backend_pid(&mut a).await;
    a.query("begin").await.unwrap();
    a.query("set local standard_conforming_strings = off")
        .await
        .unwrap();
    // The guard reads one literal; the server, with backslash escapes, runs a session-level SET
    // of a parameter it does not report.
    a.query("select '\\''; set work_mem = '7MB'; --'")
        .await
        .unwrap();
    a.query("commit").await.unwrap();
    assert_eq!(
        a.params
            .get("standard_conforming_strings")
            .map(String::as_str),
        Some("on")
    );
    let mut b = lokaj.login(&alice).await;
    assert_eq!(b.query_one("show work_mem").await, original);
    assert_ne!(backend_pid(&mut b).await, pid);
    assert_eq!(
        lokaj
            .metric("lokaj_server_recycles_total{reason=\"dirty\"}")
            .await,
        1.0
    );
}

#[tokio::test]
async fn large_results_stream_through() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    assert_eq!(
        a.query_one("select length(repeat('x', 20000000))").await,
        "20000000"
    );
    let rows = a.query("select repeat('y', 20000000)").await.unwrap();
    assert_eq!(rows[0][0].as_ref().unwrap().len(), 20_000_000);
    assert_eq!(
        a.query("select generate_series(1, 100000)")
            .await
            .unwrap()
            .len(),
        100_000
    );
}

#[tokio::test]
async fn concurrent_clients_never_see_another_tenant() {
    require_pg!();
    let lokaj = std::sync::Arc::new(Lokaj::with(|c| c.pool.max_size = 3).await);
    let mut tenants = Vec::new();
    for _ in 0..4 {
        tenants.push(std::sync::Arc::new(tenant().await));
    }
    let mut tasks = Vec::new();
    for t in &tenants {
        for _ in 0..8 {
            let lokaj = lokaj.clone();
            let t = t.clone();
            tasks.push(tokio::spawn(async move {
                let mut client = lokaj.login(&t).await;
                let mut pids = HashSet::new();
                for i in 0..40 {
                    let rows = if i % 2 == 0 {
                        client
                            .query("select current_user, current_database(), pg_backend_pid()")
                            .await
                            .unwrap()
                    } else {
                        client
                            .extended(
                                "select current_user, current_database(), pg_backend_pid()",
                                &[],
                            )
                            .await
                            .unwrap()
                    };
                    assert_eq!(rows[0][0].as_deref(), Some(t.user.as_str()));
                    assert_eq!(rows[0][1].as_deref(), Some(t.database.as_str()));
                    pids.insert(rows[0][2].clone().unwrap());
                }
                (t.user.clone(), pids)
            }));
        }
    }
    let mut by_tenant: HashMap<String, HashSet<String>> = HashMap::new();
    for task in tasks {
        let (user, pids) = task.await.unwrap();
        by_tenant.entry(user).or_default().extend(pids);
    }
    let mut seen = HashSet::new();
    for pids in by_tenant.values() {
        assert!(pids.len() <= 3);
        for pid in pids {
            assert!(
                seen.insert(pid.clone()),
                "a server connection served two tenants"
            );
        }
    }
}

#[tokio::test]
async fn password_change_on_the_server() {
    require_pg!();
    let lokaj = Lokaj::with(|c| {
        c.auth.verify_ttl = Duration::from_millis(500);
        c.server.idle_timeout = Duration::from_millis(500);
    })
    .await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    a.query("select 1").await.unwrap();
    admin()
        .await
        .query(&format!(
            "alter role \"{}\" password 'new-password'",
            alice.user
        ))
        .await
        .unwrap();
    // Wait until the verification expired and the reaper closed the idle connection.
    tokio::time::sleep(Duration::from_millis(2000)).await;
    a.send(&query("select 1")).await;
    assert_eq!(a.expect_fatal().await.code, "28P01");
    let mut client = lokaj.client().await;
    assert_eq!(
        client
            .login(&alice.params(), &alice.password)
            .await
            .unwrap_err()
            .code,
        "28P01"
    );
    let mut client = lokaj.client().await;
    client.login(&alice.params(), "new-password").await.unwrap();
    client.query("select 1").await.unwrap();
}

#[tokio::test]
async fn drain_serves_clients_then_closes_them_at_their_next_idle_point() {
    require_pg!();
    let mut lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut idle = lokaj.login(&alice).await;
    let mut busy = lokaj.login(&alice).await;
    busy.query("begin").await.unwrap();
    assert_eq!(lokaj.http("/readyz").await.0, 200);

    let stopped = lokaj.shutdown();
    lokaj.until_draining().await;
    let mut late = lokaj.client().await;
    late.send_startup(&alice.params()).await;
    assert_eq!(late.expect_fatal().await.code, "57P03");
    // Until `drain_wait` passes, connected clients are served as usual.
    idle.query("select 1").await.unwrap();

    assert_eq!(idle.expect_fatal().await.code, "57P01");
    busy.query("select 1").await.unwrap();
    busy.send(&query("commit")).await;
    let (_, error, status) = busy.results().await;
    assert!(error.is_none());
    assert_eq!(status, b'I');
    assert_eq!(busy.expect_fatal().await.code, "57P01");
    tokio::time::timeout(Duration::from_secs(5), stopped)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn drain_ends_once_clients_disconnect_on_their_own() {
    require_pg!();
    let mut lokaj = Lokaj::with(|config| config.drain_wait = Duration::from_secs(8)).await;
    let alice = tenant().await;
    let mut client = lokaj.login(&alice).await;

    let stopped = lokaj.shutdown();
    lokaj.until_draining().await;
    client.query("select 1").await.unwrap();
    client.send(&terminate()).await;
    client.expect_closed().await;
    tokio::time::timeout(Duration::from_secs(2), stopped)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn admin_endpoints() {
    require_pg!();
    let lokaj = Lokaj::start().await;
    let alice = tenant().await;
    let mut a = lokaj.login(&alice).await;
    a.query("select 1").await.unwrap();
    assert_eq!(lokaj.http("/healthz").await.0, 200);
    let (status, pools) = lokaj.http("/pools").await;
    assert_eq!(status, 200);
    let pools: serde_json::Value = serde_json::from_str(&pools).unwrap();
    assert_eq!(pools[0]["user"], alice.user.as_str());
    assert_eq!(pools[0]["servers_idle"], 1);
    let sample = format!(
        "lokaj_pool_servers_idle{{user=\"{}\",database=\"{}\"}}",
        alice.user, alice.database
    );
    assert_eq!(lokaj.metric(&sample).await, 1.0);
    let (_, metrics) = lokaj.http("/metrics").await;
    assert_eq!(
        lokaj
            .metric("lokaj_pool_wait_seconds_count{source=\"idle\"}")
            .await,
        1.0
    );
    assert_eq!(lokaj.metric("lokaj_servers_max").await, 300.0);
    assert!(!metrics.contains(&alice.password));
}
