// Chaos scenarios under steady read load: a primary and a hot-standby reader in Docker, lokaj in
// a container that resolves `reader` through a hosts file this script rewrites. Each scenario
// reports how long errors lasted after the disruption. Run through `scripts/chaos.sh`.
import assert from 'node:assert/strict'
import { execFile, execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { setTimeout as sleep } from 'node:timers/promises'
import { promisify } from 'node:util'
import pg from 'pg'

const image = process.env.LOKAJ_CHAOS_IMAGE ?? 'lokaj:dev'
const pki = process.env.LOKAJ_CHAOS_PKI
const id = `lokaj-chaos-${process.pid}`
const octet = 20 + (process.pid % 200)
const subnet = `172.31.${octet}`
const ip = { primary: `${subnet}.10`, replica: `${subnet}.11`, lokaj: `${subnet}.20` }
const RECOVERY_LIMIT_MS = 30_000

// Asynchronous, so the load keeps running and recording while a scenario acts.
const docker = async (...args) => (await promisify(execFile)('docker', args, { encoding: 'utf8' })).stdout.trim()
const log = (...args) => console.log(new Date().toISOString().slice(11, 23), ...args)

function setReader(target) {
	// Rewritten in place: lokaj sees the bind-mounted file's new content on its next lookup.
	writeFileSync(`${pki}/hosts`, `127.0.0.1 localhost\n${ip[target]} reader\n`)
	log(`reader -> ${target}`)
}

// Synchronous: it also runs from the `exit` handler.
function cleanup() {
	const run = (...args) => execFileSync('docker', args, { stdio: 'ignore' })
	for (const name of ['lokaj', 'replica', 'primary']) {
		try {
			run('rm', '-f', `${id}-${name}`)
		} catch {}
	}
	try {
		run('network', 'rm', id)
	} catch {}
}

async function waitFor(what, check, limitMs = 60_000) {
	const deadline = Date.now() + limitMs
	for (;;) {
		try {
			if (await check()) return
		} catch {}
		if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`)
		await sleep(250)
	}
}

const psql = (container, sql) =>
	docker('exec', '-e', 'PGPASSWORD=postgres', container, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-tAc', sql)

// Both servers use TLS with the test certificate, whose name `reader` lokaj verifies. The key
// must belong to the server's user.
const tlsMounts = ['-v', `${pki}/server.crt:/tls/server.crt:ro`, '-v', `${pki}/server.key:/tls/server.key:ro`]
const tlsOptions = '-c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tmp/server.key'

async function startReplica() {
	await docker('run', '-d', '--name', `${id}-replica`, '--network', id, '--ip', ip.replica, '--user', 'postgres',
		...tlsMounts, '-e', 'PGPASSWORD=replicator', '--entrypoint', 'bash', 'postgres:18', '-c',
		`install -m 600 /tls/server.key /tmp/server.key; [ -f /tmp/pgdata/PG_VERSION ] || pg_basebackup -h primary -U replicator -D /tmp/pgdata -R -X stream -c fast; chmod 700 /tmp/pgdata; exec postgres -D /tmp/pgdata -c max_connections=500 ${tlsOptions}`)
}

async function setup() {
	cleanup()
	await docker('network', 'create', '--subnet', `${subnet}.0/24`, id)
	await docker('run', '-d', '--name', `${id}-primary`, '--network', id, '--ip', ip.primary, '--network-alias', 'primary',
		...tlsMounts, '-e', 'POSTGRES_PASSWORD=postgres', '-e', 'POSTGRES_HOST_AUTH_METHOD=scram-sha-256',
		'-e', 'POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256', '--entrypoint', 'bash', 'postgres:18', '-c',
		`install -o postgres -m 600 /tls/server.key /tmp/server.key; exec docker-entrypoint.sh postgres -c max_connections=500 ${tlsOptions}`)
	// During initdb the entrypoint's temporary server listens on the Unix socket only.
	await waitFor('primary', async () => (await psql(`${id}-primary`, 'select 1')) === '1')
	await psql(`${id}-primary`, "create role replicator replication login password 'replicator'")
	await docker('exec', `${id}-primary`, 'bash', '-c', 'echo "host replication replicator all scram-sha-256" >> "$PGDATA/pg_hba.conf"')
	await psql(`${id}-primary`, 'select pg_reload_conf()')

	const tenants = []
	for (let i = 0; i < 6; i++) {
		const name = `c_${randomBytes(5).toString('hex')}`
		const password = randomBytes(12).toString('base64url')
		await psql(`${id}-primary`, `create role "${name}" login password '${password}'`)
		await psql(`${id}-primary`, `create database "${name}" owner "${name}"`)
		await docker('exec', '-e', `PGPASSWORD=${password}`, `${id}-primary`, 'psql', '-h', '127.0.0.1', '-U', name, '-d', name, '-c',
			'create table item (id int primary key, label text); insert into item select g, md5(g::text) from generate_series(1, 1000) g')
		tenants.push({ user: name, database: name, password })
	}

	await startReplica()
	await replicaReady()

	setReader('replica')
	writeFileSync(`${pki}/lokaj.toml`, `
listen = "0.0.0.0:6432"
admin_listen = "0.0.0.0:9930"
shutdown_timeout = "20s"
[tls]
cert = "/etc/lokaj/server.crt"
key = "/etc/lokaj/server.key"
[server]
host = "reader"
ca = "/etc/lokaj/ca.crt"
dns_forget_after = "5s"
check_after = "5s"
connect_timeout = "3s"
[pool]
max_size = 6
`)
	await startLokaj()
	return tenants
}

let lokajPorts
const replicaReady = () => waitFor('replica', async () => (await psql(`${id}-replica`, 'select pg_is_in_recovery()')) === 't')

async function startLokaj() {
	await docker('run', '-d', '--name', `${id}-lokaj`, '--network', id, '--ip', ip.lokaj,
		'-v', `${pki}:/etc/lokaj:ro`, '-v', `${pki}/hosts:/etc/hosts:ro`,
		'-p', '127.0.0.1::6432', '-p', '127.0.0.1::9930', image)
	const port = async inner => Number((await docker('port', `${id}-lokaj`, `${inner}/tcp`)).split('\n')[0].split(':').pop())
	lokajPorts = { pg: await port(6432), admin: await port(9930) }
}

async function lokajReady() {
	await waitFor('lokaj', async () => (await fetch(`http://127.0.0.1:${lokajPorts.admin}/readyz`)).ok)
}

/** Steady load: each loop runs an engine-style read transaction and records the outcome. */
function startLoad(tenants) {
	const ca = readFileSync(`${pki}/ca.crt`, 'utf8')
	const events = []
	let running = true
	const pools = []
	const loops = []
	for (const tenant of tenants) {
		for (let pod = 0; pod < 3; pod++) {
			// Ports change when the lokaj container is recreated, so pools resolve them per connection.
			const pool = new pg.Pool({
				max: 3,
				user: tenant.user,
				password: tenant.password,
				database: tenant.database,
				ssl: { ca, servername: 'localhost' },
				host: '127.0.0.1',
				connectionTimeoutMillis: 3000,
				idleTimeoutMillis: 5000,
			})
			Object.defineProperty(pool.options, 'port', { get: () => lokajPorts.pg })
			pool.on('error', error => events.push({ t: Date.now(), ok: false, idle: true, code: error.code ?? error.message }))
			// A checked-out client also emits `error` when its connection drops; the query rejects anyway.
			pool.on('connect', client => client.on('error', () => {}))
			pools.push(pool)
			for (let c = 0; c < 3; c++) {
				loops.push((async () => {
					while (running) {
						let client
						try {
							client = await pool.connect()
							await client.query('BEGIN', [])
							await client.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
							const result = await client.query(
								'select pg_is_in_recovery() as standby, current_database() as db, count(*)::int as n from item where id > $1',
								[Math.floor(Math.random() * 500)],
							)
							await client.query('COMMIT')
							client.release()
							const row = result.rows[0]
							assert.equal(row.db, tenant.database)
							events.push({ t: Date.now(), ok: true, standby: row.standby })
						} catch (error) {
							client?.release(true)
							events.push({ t: Date.now(), ok: false, code: error.code ?? error.message })
						}
						await sleep(10)
					}
				})())
			}
		}
	}
	return {
		events,
		async stop() {
			running = false
			await Promise.all(loops)
			await Promise.all(pools.map(pool => pool.end().catch(() => {})))
		},
	}
}

/** Outcomes recorded after `since`, and when the last error was seen relative to `since`. */
function summarize(events, since, until = Date.now()) {
	const window = events.filter(e => e.t >= since && e.t <= until && !e.idle)
	const errors = window.filter(e => !e.ok)
	const codes = {}
	for (const error of errors) codes[error.code] = (codes[error.code] ?? 0) + 1
	const lastError = errors.length ? Math.max(...errors.map(e => e.t)) - since : 0
	return { total: window.length, errors: errors.length, codes, lastErrorMs: lastError }
}

async function steady(load, ms) {
	const since = Date.now()
	await sleep(ms)
	const summary = summarize(load.events, since)
	assert.ok(summary.total > 100, `too little traffic: ${JSON.stringify(summary)}`)
	assert.equal(summary.errors, 0, `errors in steady state: ${JSON.stringify(summary)}`)
}

async function scenario(name, load, action, { settle = 15_000 } = {}) {
	log(`scenario: ${name}`)
	const since = Date.now()
	await action()
	await sleep(settle)
	const summary = summarize(load.events, since)
	log(`  ${JSON.stringify(summary)}`)
	assert.ok(summary.lastErrorMs <= RECOVERY_LIMIT_MS, `${name}: recovery took ${summary.lastErrorMs} ms`)
	await steady(load, 3000)
	return { name, ...summary }
}

/** Milliseconds after `since` until every transaction ran on the expected kind of server. */
async function untilAll(load, since, standby, limitMs = RECOVERY_LIMIT_MS) {
	await waitFor(`all reads on ${standby ? 'the standby' : 'the writer'}`, () => {
		const recent = load.events.filter(e => e.ok && e.t > Date.now() - 2000)
		return recent.length > 50 && recent.every(e => e.standby === standby)
	}, limitMs + 5000)
	const wrong = load.events.filter(e => e.ok && e.t >= since && e.standby !== standby)
	return wrong.length ? Math.max(...wrong.map(e => e.t)) - since : 0
}

async function main() {
	const results = []
	let load
	// Also runs after an uncaught exception, which skips `finally`.
	if (!process.env.LOKAJ_CHAOS_KEEP) process.on('exit', cleanup)
	try {
		const tenants = await setup()
		await lokajReady()
		load = startLoad(tenants)
		await steady(load, 5000)

		results.push(await scenario('reader reboot', load, () => docker('restart', '-t', '2', `${id}-replica`)))

		results.push(await scenario('reader down, endpoint falls back to the writer', load, async () => {
			await docker('stop', '-t', '2', `${id}-replica`)
			setReader('primary')
		}))
		assert.ok(load.events.filter(e => e.ok && e.t > Date.now() - 2000).every(e => e.standby === false))

		let since = Date.now()
		await docker('start', `${id}-replica`)
		await replicaReady()
		setReader('replica')
		const switchedBack = await untilAll(load, since, true)
		log(`  reader back: all reads on the standby after ${switchedBack} ms`)
		results.push({ name: 'reader back, writer connections recycled', ...summarize(load.events, since), switchedBackMs: switchedBack })
		assert.equal(summarize(load.events, since).errors, 0)

		results.push(await scenario('pooler killed mid-transaction', load, async () => {
			await docker('kill', `${id}-lokaj`)
			await docker('rm', `${id}-lokaj`)
			await startLokaj()
		}))

		log('scenario: graceful drain')
		const ca = readFileSync(`${pki}/ca.crt`, 'utf8')
		const long = new pg.Client({ ...tenants[0], host: '127.0.0.1', port: lokajPorts.pg, ssl: { ca, servername: 'localhost' } })
		long.on('error', () => {})
		await long.connect()
		await long.query('BEGIN')
		const inFlight = long.query('select pg_sleep(3)').then(() => long.query('COMMIT'))
		since = Date.now()
		await docker('kill', '--signal', 'TERM', `${id}-lokaj`)
		await inFlight
		log('  in-flight transaction committed during the drain')
		await waitFor('lokaj to exit', async () => (await docker('inspect', '-f', '{{.State.Running}}', `${id}-lokaj`)) === 'false', 25_000)
		const drain = summarize(load.events, since)
		const unexpected = Object.keys(drain.codes).filter(code => !['57P01', '57P03'].includes(code) && !/terminat|ECONNREFUSED|ECONNRESET|timeout/i.test(code))
		log(`  ${JSON.stringify(drain)}`)
		assert.deepEqual(unexpected, [], `unexpected errors during the drain: ${unexpected}`)
		await docker('rm', `${id}-lokaj`)
		await startLokaj()
		await lokajReady()
		await sleep(10_000)
		await steady(load, 3000)
		results.push({ name: 'graceful drain', ...drain })
	} finally {
		await load?.stop()
		console.log(JSON.stringify(results, null, 2))
	}
}

main().catch(error => {
	console.error(error)
	process.exitCode = 1
})
