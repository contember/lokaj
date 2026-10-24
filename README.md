# lokaj

A read-only PostgreSQL connection pooler in transaction mode, for many tenant databases behind
one reader endpoint.

In a multi-tenant setup where every project has its own database and role, and every
application pod keeps its own connection pool per project, a reader ends up holding roughly
*pods × projects × burst* backends, almost all of them idle. Each backend costs memory, and each new
one costs a fork and a SCRAM exchange. lokaj sits between the application and the reader
endpoint. It hands a server connection to a client for the duration of one transaction, so
the server only holds as many backends as there are concurrent transactions.

## Scope

- **Read path only:** the client is an application's read pool pointing at a reader endpoint.
- **Transaction pooling:** a server connection belongs to a client from the first message of a
  transaction until the server is idle again.
- **Clients:** node-pg (the `pg` package), with the startup parameters and protocol subset it uses.
  It is not a general-purpose pooler.
- **Not supported:**
  - writes, session pooling and named prepared statements;
  - COPY, LISTEN and replication;
  - load balancing across readers (DNS does that).

## How it works

### Login

1. **TLS.** The client must send `SSLRequest`, and lokaj completes a TLS handshake.
   - A startup packet without TLS gets `FATAL 28000`.
   - `GSSENCRequest` is answered with `N`.
   - Protocol 3.2 and newer is answered with `NegotiateProtocolVersion` for 3.0.
2. **Startup parameters.** Accepted:
   - `user`, `database` (defaults to the user) and `application_name`;
   - `client_encoding`, which must be `UTF8`;
   - `statement_timeout`, `lock_timeout` and `idle_in_transaction_session_timeout`, as plain
     millisecond integers. These are applied to the server connections, and they are part of the
     pool key.

   Any other parameter, including `options` and `replication`, is refused with `0A000`. A user or
   database name longer than 63 bytes is refused with `42622`; the server would truncate it to
   another name.
3. **Password.** lokaj asks for a cleartext password (`AuthenticationCleartextPassword`), which
   travels inside the TLS session.
4. **Verification.** The first time a `(user, database)` pair logs in, lokaj opens a server
   connection with that password over SCRAM-SHA-256, and the server decides.
   - Server connections always use TLS, and lokaj verifies the server certificate against
     `server.host` with the CAs in `server.ca`. A server that declines TLS or presents another
     certificate is refused before the password is used.
   - Server connections accept only SCRAM-SHA-256, and lokaj verifies the server signature.
     A server asking for a cleartext or MD5 password, or for none, is refused.
   - **On success**, lokaj keeps the SCRAM `ClientKey` and `ServerKey`, plus an HMAC-SHA256 of
     user, database and password under a random per-process key. It never keeps the password.
     The verification connection joins the pool.
   - **On rejection**, the client gets the server's error (`28P01`, or `42501` for a database
     it may not connect to).
   - A server that refuses before any password exchange, as `pg_hba.conf` does, says nothing
     about the password: the client gets the server's `28000`, and the login does not count as
     failed.
   - A credential is never cached before the server has accepted it.
   - At most `auth.max_verifications` verifications run at once; a login that cannot start one
     within `pool.wait_timeout` gets `53300`.
5. **Later logins** compare the HMAC in constant time, with no server round trip.
   - A credential stays fresh for `auth.verify_ttl` after its last successful server login;
     after that the next login verifies against the server again.
   - Concurrent first logins for one pair share a single verification.
6. **Rate limiting.** lokaj must not become a password oracle against the server. Failures are
   counted within `auth.failure_window`, in two ways, and a refused login gets `28P01`:
   - **Per user and client address.** After `auth.max_failures` failed logins, that address is
     refused for that user, even with the right password, so it cannot test guesses against
     the cache either. Each refused attempt counts as another failure.
   - **Per user, across all addresses.** Failed and running verifications together stay below
     `auth.max_failures`. Past that, a login that needs a server verification is refused
     without reaching the server. Logins that match a fresh cached credential still succeed.

   The second limit is a trade-off: a client that can reach lokaj from many addresses can fail
   logins for a user on purpose and block its new verifications for one window. Clients with a
   cached credential are not affected.
7. **Pool.** Only now does lokaj create the client's pool, so failed logins create no pools. If
   the verification connection finds a free slot in it, it joins the pool; otherwise it is
   closed.
8. **Logged in.** The client receives:
   - `ParameterStatus` from a snapshot of a real server connection of its pool;
   - a synthetic `BackendKeyData`;
   - `ReadyForQuery 'I'`.

Passwords and authentication messages are never logged.

### Relay

**Assignment:**
- A client gets a server connection from its pool on its first message after `ReadyForQuery 'I'`.
- It gives the connection back when the server reports `ReadyForQuery 'I'` and nothing the
  client sent is still unanswered.
- In status `T` or `E` the connection stays with the client.
- A client that holds a connection while the server waits for it, idle in a transaction or in
  an unfinished extended batch, is closed with `FATAL 25P03` after
  `client.idle_transaction_timeout`, and the connection is discarded.

**Allowed messages:**
- simple `Query`;
- `Parse`, `Bind`, `Describe`, `Execute` and `Close` on the unnamed statement and portal;
- `Sync`, `Flush` and `Terminate`.

`Bind`, `Describe` and `Execute` must refer to an object created in the same batch, after the
last `Sync`. This way a client never uses an unnamed statement another client left on the
connection, nor one that an earlier failed `Parse` did not replace.

**Refused, closing the client:**
- named statements and portals (`0A000`);
- `FunctionCall` (`0A000`);
- COPY in either direction (`0A000`);
- a simple query inside an unfinished extended batch (`08P01`);
- `Bind`, `Describe` or `Execute` without its creating message in the same batch (`26000`).

**Session-state guard.** A lexical guard checks every statement, including those sent with
`Parse`. It understands comments, all string and identifier quoting forms, and dollar quotes.
It refuses:
- `SET`, except `SET LOCAL` and `SET TRANSACTION`;
- `RESET`, `DISCARD`, `PREPARE` and `LISTEN`;
- `DECLARE … WITH HOLD`.

**Read-only sessions.** Server connections start with `default_transaction_read_only = on`,
so writes and temporary tables fail with `25006` even when the reader endpoint falls back to
the writer. This guards against accidents only: a client can still begin a `READ WRITE`
transaction. Give the roles read-only privileges for a hard boundary.

**Server output.** Results stream to the client without being buffered. lokaj parses only
`ReadyForQuery`, `ParameterStatus` and `ErrorResponse`.

**A server connection is closed instead of returned to the pool when:**
- the client leaves in the middle of a transaction or query (if a query is running, it is
  cancelled first);
- a cancel request arrived during the assignment;
- the server reported a `ParameterStatus` that differs from the pool snapshot;
- the server sent a FATAL error or COPY data, or the connection is in any state other than
  clean and idle.

### Pools

- **Key and limits.** A pool is keyed by user, database and startup options.
  - One database has at most two pools at a time, for example with and without a statement
    timeout. A login with a third set of options gets `0A000`, so one tenant cannot spread
    over many pools.
  - Per pool, at most `pool.max_size` server connections and `pool.max_waiters` waiting clients.
  - A client waits at most `pool.wait_timeout`, then gets `53300`.
  - Across pools, at most `pool.max_total` connections. When that is full, lokaj closes the
    oldest idle connection of another pool rather than letting a client wait.
- **Lifecycle.**
  - No minimum size, and no background connects: a connection is opened only for a waiting
    client.
  - Connections close after `server.idle_timeout` idle, or after `server.lifetime` plus random
    jitter.
  - Server and client connections use TCP keepalive after `server.keepalive_time`, and
    `TCP_USER_TIMEOUT` closes them when sent data stays unacknowledged for 30 s longer. A peer
    that vanishes mid-query is noticed within about a minute.
  - A connection idle longer than `server.check_after` gets one round trip before reuse.
  - Empty pools are dropped after `pool.gc_after`.
- **Snapshot.** When a new server connection reports different parameters, the snapshot moves
  on and older connections are retired.

### DNS

- `server.host` is resolved for each new connection, cached for `server.dns_cache_ttl`, and
  refreshed every `server.dns_refresh_interval`.
- An address absent from every answer for `server.dns_forget_after` is treated as gone, and its
  connections are recycled: idle ones on reuse, assigned ones on release.

The window spans several lookups because a reader endpoint may return one reader per answer. It
covers a reader reboot, a failover, and the endpoint falling back to the writer.

### Cancel

- A cancel key is random and checked in constant time.
- It maps only to the server connection currently assigned to that client; with no assignment,
  the cancel is dropped.
- The cancelled server connection is discarded afterwards, so a late cancel can never hit
  another client's query.
- lokaj sends the cancel request to the server over TLS, like the connection it cancels.

### Drain

On SIGTERM or SIGINT:
- `/readyz` returns 503;
- new clients get `57P03`;
- idle clients get `FATAL 57P01`;
- clients inside a transaction are closed at their next idle point.

lokaj exits as soon as no clients remain, and at the latest after `shutdown_timeout` (55 s).
- Give the pod a grace period of about 60 s.
- Add a `preStop` sleep of a few seconds. It keeps an idle pooler answering until the Service
  stops routing to it.

## Running

```sh
cargo build --release
target/release/lokaj lokaj.toml        # or LOKAJ_CONFIG=lokaj.toml
docker build -t lokaj .                # reads /etc/lokaj/lokaj.toml
```

[`lokaj.example.toml`](lokaj.example.toml) lists every setting with its default. Logging:
- `LOKAJ_LOG` takes a `tracing` filter (default `info`);
- `LOKAJ_LOG_FORMAT=json` switches to JSON lines.

Clients need TLS that verifies the pooler's certificate:

```js
new pg.Pool({ host: 'lokaj.internal', port: 6432, ssl: { ca }, user, password, database })
```

Alternatively, set `ssl: true` and add the CA through `NODE_EXTRA_CA_CERTS`.

Server connections use TLS and verify the server's certificate against `server.host`, with
the CAs in `server.ca`; for Amazon RDS and Aurora that is the RDS CA bundle. Certificates and
CAs are read at startup; rotate them with a rolling restart.

## Admin HTTP

| Path       | Response                                                                 |
| ---------- | ------------------------------------------------------------------------ |
| `/metrics` | Prometheus (OpenMetrics text)                                            |
| `/healthz` | 200 while the process runs                                               |
| `/readyz`  | 200, or 503 while draining                                               |
| `/pools`   | JSON list of pools with key, clients, waiters and server connections    |

All metrics are prefixed `lokaj_`.

| Metric                                                  | Labels             | Meaning                                         |
| ------------------------------------------------------- | ------------------ | ----------------------------------------------- |
| `clients`                                               |                    | connected client sessions                       |
| `client_rejects_total`                                  | `reason`           | connections refused before the session started  |
| `server_connects_total`                                 |                    | server connections established                  |
| `server_connect_errors_total`                           | `reason`           | failed server connection attempts               |
| `server_recycles_total`                                 | `reason`           | server connections closed by lokaj              |
| `servers`                                               |                    | open server connections                         |
| `auth_failures_total`                                   | `reason`           | rejected client logins                          |
| `credential_cache_total`                                | `result`           | logins answered from the cache (`hit`/`miss`)   |
| `dns_changes_total`                                     |                    | changes of the server address set               |
| `cancels_total`                                         | `result`           | cancel requests                                 |
| `pool_wait_seconds`                                     | `user`, `database` | time clients waited for a server connection     |
| `pool_transactions_total`                               | `user`, `database` | completed assignments                           |
| `pool_clients`, `pool_clients_active`, `pool_clients_waiting` | `user`, `database` | clients logged in, assigned, waiting      |
| `pool_servers_active`, `pool_servers_idle`              | `user`, `database` | server connections                              |

## Errors sent to clients

| Code    | When                                                                        |
| ------- | --------------------------------------------------------------------------- |
| `28000` | no TLS, or no user name                                                     |
| `28P01` | wrong password, rate-limited login, or server-side authentication failure   |
| `42622` | a user or database name longer than 63 bytes                                |
| `53300` | pool wait timeout, too many waiters, or too many logins being verified      |
| `25P03` | the client held a server connection idle for too long                       |
| `57P03` | lokaj is draining                                                           |
| `57P01` | lokaj is draining and the client is idle                                    |
| `08006` | server unreachable or untrusted, or a connection lost mid-transaction      |
| `0A000` | an unsupported message, parameter or statement, or a third set of options   |
| `08P01` | a protocol violation                                                        |

Server errors during connection setup, such as a database that does not exist or a server
that is starting up, are passed through as the server sent them.

## Differences from a direct connection

- **Session state.** It lives only within one transaction.
  - `SET` without `LOCAL` is refused, and so is `SET CONSTRAINTS`.
  - Session state the guard cannot see stays on the server connection and is visible to later
    transactions of the same pool, never of another pool. Examples: `set_config(…, false)` on a
    parameter the server does not report, temporary tables, session advisory locks.
- **`application_name`.** The client's value is echoed back to it, but the server sees
  `server.application_name`.
- **Process identity.** `pg_backend_pid()` changes between transactions. Cancel keys are
  synthetic, and a cancel sent to another lokaj replica is ignored.
- **Password change on the server.** Logins with the old password keep working from the cache
  until a new server connection is needed or `auth.verify_ttl` passes. Then the server rejects
  the cached keys, the entry is dropped, and that client gets `28P01`.
- **String escapes.** The guard assumes the default `standard_conforming_strings = on`; clients
  cannot change it through lokaj.

## Development

```sh
cargo test                              # unit and property tests
scripts/integration.sh [rust|node]      # PostgreSQL 18 in Docker: protocol suite and node-pg suite
scripts/chaos.sh                        # primary + hot standby: reader reboot, fallback to the writer, pooler kill, drain
cpu-lease run -n 6 -- scripts/load.sh   # load test on three reserved SMT pairs
cargo +nightly fuzz run frontend        # also: startup, sql_guard, backend_stream
```

The load test simulates engine pods with a pool per project:
- 1000 projects;
- two busy projects at 438 and 225 transactions/s spread over 8 and 12 pods;
- a warm set of 18 projects;
- a trickle of cold projects;
- 15 new client connections/s.

It runs this load first directly against PostgreSQL and then through two lokaj replicas, then
logs in to every project once while the load continues. It reports throughput, latency, server
backends, new backends per second and lokaj's CPU and memory. Added latency is measured by a
probe that alternates direct and pooled transactions under the same load.

## License

MIT
