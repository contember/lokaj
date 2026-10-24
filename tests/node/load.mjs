// Load test: production-shaped read traffic from simulated engine pods, first directly against
// PostgreSQL and then through the lokaj replicas, followed by a login sweep over every project
// while the load keeps running. Added latency comes from a probe that rotates direct, direct TLS
// and lokaj transactions under the same load. Run through `scripts/load.sh`, which pins the CPUs.
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { setTimeout as sleep } from 'node:timers/promises'
import { Worker } from 'node:worker_threads'
import pg from 'pg'
import { readTransaction, STEPS } from './load-shape.mjs'

const env = (name, fallback) => process.env[name] ?? fallback
const TENANTS = Number(env('LOKAJ_LOAD_TENANTS', 1000))
const DURATION = Number(env('LOKAJ_LOAD_DURATION', 60)) * 1000
// Longer than the server idle timeout, so connections opened by the cold start have expired.
const WARMUP = Number(env('LOKAJ_LOAD_WARMUP', 75)) * 1000
const SCALE = Number(env('LOKAJ_LOAD_SCALE', 1))
const WORKERS = Number(env('LOKAJ_LOAD_WORKERS', 2))
const [pgHost, pgPort] = env('LOKAJ_LOAD_PG').split(':')
const lokajPorts = env('LOKAJ_LOAD_LOKAJ').split(',').map(Number)
// Empty for a pooler other than lokaj, whose own metrics are then left out.
const adminUrls = env('LOKAJ_LOAD_ADMIN').split(',').filter(Boolean).map(address => `http://${address}`)
const lokajPids = env('LOKAJ_LOAD_PIDS').split(',').map(Number)
const ca = readFileSync(env('LOKAJ_LOAD_CA'), 'utf8')

const CRITERIA = { backends: 200, newBackendsPerSecond: 2, addedP50: 0.3, addedP99: 2, rssMiB: 256 }

// Production shape: two busy projects spread over many pods, a warm set that makes ~20 databases
// active per minute, a trickle of cold projects and steady client connection churn.
const HOT = [
	{ rate: 438, pods: 8 },
	{ rate: 225, pods: 12 },
]
const WARM = { projects: 18, rate: 700, pods: 4 }
const CHURN_RATE = 15
const COLD_RATE = 0.3
const PROBE = 'lokaj-probe'
// Set by `scripts/load.sh` when the pooled phase runs through another pooler, for the report.
const POOLER = env('LOKAJ_LOAD_POOLER', 'lokaj')

const direct = { host: pgHost, ports: [Number(pgPort)], ssl: false }
const viaLokaj = { host: '127.0.0.1', ports: lokajPorts, ssl: { ca, servername: 'localhost' } }

const admin = (database = 'postgres') =>
	new pg.Client({ host: pgHost, port: Number(pgPort), user: 'postgres', password: 'postgres', database })
const log = (...args) => console.log(new Date().toISOString().slice(11, 19), ...args)

async function setup() {
	const root = admin()
	await root.connect()
	await root.query('create database load_template')
	const template = admin('load_template')
	await template.connect()
	await template.query(`
		create table author (id int primary key, name text not null);
		create table article (
			id int primary key, author_id int not null references author, title text not null,
			published_at timestamptz not null, views int not null
		);
		create index on article (published_at);
		create index on article (author_id);
		insert into author select g, 'Author ' || g from generate_series(1, 20) g;
		insert into article select g, 1 + g % 20, 'Article ' || g, now() - g * interval '1 hour', (g * 7919) % 1000
			from generate_series(1, 500) g;
		grant select on all tables in schema public to public;
		analyze;
	`)
	await template.end()

	const tenants = Array.from({ length: TENANTS }, (_, i) => {
		const name = `p_${String(i).padStart(4, '0')}`
		return { user: name, database: name, password: randomBytes(12).toString('base64url') }
	})
	const queue = [...tenants]
	const started = Date.now()
	await Promise.all(
		Array.from({ length: 4 }, async () => {
			const client = admin()
			await client.connect()
			for (let tenant = queue.pop(); tenant; tenant = queue.pop()) {
				await client.query(`create role "${tenant.user}" login password '${tenant.password}'`)
				await client.query(`create database "${tenant.database}" owner "${tenant.user}" template load_template`)
				await client.query(`revoke connect on database "${tenant.database}" from public`)
			}
			await client.end()
		}),
	)
	log(`created ${TENANTS} roles and databases in ${((Date.now() - started) / 1000).toFixed(0)} s`)
	// Otherwise a timed checkpoint flushes the setup's writes in the middle of a measurement.
	await root.query('CHECKPOINT')
	return { root, tenants }
}

function plan(tenants) {
	const streams = HOT.map((hot, i) => ({ tenant: tenants[i], ...hot }))
	const warm = tenants.slice(HOT.length, HOT.length + WARM.projects)
	const weights = warm.map((_, i) => 1 / (i + 1))
	const total = weights.reduce((a, b) => a + b, 0)
	warm.forEach((tenant, i) => streams.push({ tenant, rate: (WARM.rate * weights[i]) / total, pods: WARM.pods }))

	const pods = streams
		.flatMap(stream => Array.from({ length: stream.pods }, () => ({ tenant: stream.tenant, rate: (stream.rate * SCALE) / stream.pods })))
		.sort((a, b) => b.rate - a.rate)
	const active = tenants.slice(0, HOT.length + WARM.projects)
	const cold = tenants.slice(active.length)
	return Array.from({ length: WORKERS }, (_, w) => ({
		pods: pods.filter((_, i) => i % WORKERS === w),
		churn: { rate: (CHURN_RATE * SCALE) / WORKERS, tenants: active },
		cold: { rate: COLD_RATE / WORKERS, tenants: cold.filter((_, i) => i % WORKERS === w) },
	}))
}

const request = (worker, message) =>
	new Promise(resolve => {
		worker.once('message', resolve)
		worker.postMessage(message)
	})

function merge(replies) {
	const merged = { tx: [], acquire: [], logins: [], errors: {}, mismatches: 0, slow: [], loopP99: 0, loopMax: 0 }
	for (const { stats } of replies) {
		merged.loopP99 = Math.max(merged.loopP99, stats.loopP99)
		merged.loopMax = Math.max(merged.loopMax, stats.loopMax)
		merged.tx.push(...stats.tx)
		merged.acquire.push(...stats.acquire)
		merged.logins.push(...stats.logins)
		merged.slow.push(...stats.slow)
		merged.mismatches += stats.mismatches
		for (const [code, n] of Object.entries(stats.errors)) merged.errors[code] = (merged.errors[code] ?? 0) + n
	}
	return merged
}

function percentiles(values) {
	const sorted = Float64Array.from(values).sort()
	const at = q => (sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] : NaN)
	return { n: sorted.length, p50: at(0.5), p99: at(0.99), p999: at(0.999), max: sorted.at(-1) ?? NaN }
}

const CLK_TCK = Number(execFileSync('getconf', ['CLK_TCK'], { encoding: 'utf8' }))
function cpuSeconds(pid) {
	const stat = readFileSync(`/proc/${pid}/stat`, 'utf8')
	const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ')
	return (Number(fields[11]) + Number(fields[12])) / CLK_TCK
}
function memoryMiB(pid) {
	const status = readFileSync(`/proc/${pid}/status`, 'utf8')
	const kib = field => Number(status.match(new RegExp(`${field}:\\s+(\\d+)`))[1])
	return { rss: kib('VmRSS') / 1024, peak: kib('VmHWM') / 1024 }
}

const assignedServers = async () =>
	(await Promise.all(adminUrls.map(async url => (await fetch(`${url}/pools`)).json())))
		.flat()
		.reduce((n, pool) => n + pool.servers_active, 0)

/** Samples PostgreSQL client backends and lokaj's assigned server connections once a second. */
function sampleBackends(root) {
	const samples = []
	const assigned = []
	let stopped = false
	const done = (async () => {
		while (!stopped) {
			const result = await root.query(
				`select count(*)::int as n from pg_stat_activity
				where backend_type = 'client backend' and pid <> pg_backend_pid() and application_name <> $1`,
				[PROBE],
			)
			samples.push(result.rows[0].n)
			assigned.push(await assignedServers())
			await sleep(1000)
		}
	})()
	return async () => {
		stopped = true
		await done
		return {
			max: Math.max(...samples),
			avg: samples.reduce((a, b) => a + b, 0) / samples.length,
			assignedMax: Math.max(...assigned),
		}
	}
}

const sessions = async root =>
	Number((await root.query('select sum(sessions)::bigint as n from pg_stat_database')).rows[0].n)

/** A measured window over the running load: throughput, latencies and the server-side footprint. */
async function window(name, root, workers, ms, during) {
	const stopSampling = sampleBackends(root)
	const sessionsBefore = await sessions(root)
	const cpuBefore = lokajPids.map(cpuSeconds)
	const generatorBefore = process.cpuUsage()
	const waitsBefore = await poolWaits()
	const started = performance.now()
	const extra = during ? await during() : await sleep(ms)
	const seconds = (performance.now() - started) / 1000
	const generator = process.cpuUsage(generatorBefore)
	const stats = merge(await Promise.all(workers.map(worker => request(worker, { type: 'mark' }))))
	const backends = await stopSampling()
	const waitsAfter = await poolWaits()
	return {
		name,
		seconds,
		txPerSecond: stats.tx.length / seconds,
		tx: percentiles(stats.tx),
		acquire: percentiles(stats.acquire),
		logins: percentiles(stats.logins),
		errors: stats.errors,
		mismatches: stats.mismatches,
		slow: stats.slow,
		backends,
		newBackendsPerSecond: ((await sessions(root)) - sessionsBefore) / seconds,
		lokajCpu: lokajPids.map((pid, i) => (cpuSeconds(pid) - cpuBefore[i]) / seconds),
		generatorCpu: (generator.user + generator.system) / 1e6 / seconds,
		loop: { p99: stats.loopP99, max: stats.loopMax },
		waits: Object.fromEntries(Object.entries(waitsAfter).map(([le, n]) => [le, n - (waitsBefore[le] ?? 0)])),
		lokajMemory: lokajPids.map(memoryMiB),
		extra,
	}
}

async function phase(target, workers) {
	await Promise.all(workers.map(worker => request(worker, { type: 'start', target })))
	await sleep(WARMUP)
	await Promise.all(workers.map(worker => request(worker, { type: 'mark' })))
}

const stop = workers => Promise.all(workers.map(worker => request(worker, { type: 'stop' })))

/**
 * A direct, a direct TLS and a lokaj client per tenant, taking turns with the same transaction, so
 * every arm sees the same server load and generator noise. Its direct backends are left out of the
 * samples. The TLS arm separates the cost of TLS from the cost of the extra hop.
 */
async function openProbe(tenants) {
	const pairs = await Promise.all(
		tenants.map(async (tenant, i) => {
			const pair = {
				tenant,
				direct: new pg.Client({ ...tenant, host: pgHost, port: Number(pgPort), application_name: PROBE }),
				tls: new pg.Client({ ...tenant, host: pgHost, port: Number(pgPort), ssl: viaLokaj.ssl, application_name: PROBE }),
				lokaj: new pg.Client({ ...tenant, host: viaLokaj.host, port: lokajPorts[i % lokajPorts.length], ssl: viaLokaj.ssl }),
			}
			await Promise.all([pair.direct.connect(), pair.tls.connect(), pair.lokaj.connect()])
			return pair
		}),
	)
	return {
		async run(ms) {
			const arms = ['direct', 'tls', 'lokaj']
			const samples = { direct: [], tls: [], lokaj: [] }
			let mismatches = 0
			const deadline = performance.now() + ms
			for (let i = 0; performance.now() < deadline; i++) {
				const pair = pairs[i % pairs.length]
				for (const arm of [...arms.slice(i % 3), ...arms.slice(0, i % 3)]) {
					const started = performance.now()
					if ((await readTransaction(pair[arm])) !== pair.tenant.database) mismatches++
					samples[arm].push(performance.now() - started)
				}
				await sleep(2)
			}
			return {
				direct: percentiles(samples.direct),
				tls: percentiles(samples.tls),
				lokaj: percentiles(samples.lokaj),
				mismatches,
			}
		},
		close: () => Promise.all(pairs.flatMap(pair => [pair.direct.end(), pair.tls.end(), pair.lokaj.end()])),
	}
}

/** Logs in to every project once through lokaj, 32 at a time. */
async function sweep(tenants) {
	const queue = [...tenants].sort(() => Math.random() - 0.5)
	const latencies = []
	const errors = {}
	let mismatches = 0
	await Promise.all(
		Array.from({ length: 32 }, async () => {
			for (let tenant = queue.pop(); tenant; tenant = queue.pop()) {
				const client = new pg.Client({
					...tenant,
					host: viaLokaj.host,
					port: lokajPorts[Math.floor(Math.random() * lokajPorts.length)],
					ssl: viaLokaj.ssl,
				})
				client.on('error', () => {})
				const started = performance.now()
				try {
					await client.connect()
					const result = await client.query('select current_database() as db')
					latencies.push(performance.now() - started)
					if (result.rows[0].db !== tenant.database) mismatches++
				} catch (error) {
					const code = error.code ?? error.message
					errors[code] = (errors[code] ?? 0) + 1
				} finally {
					await client.end().catch(() => {})
				}
			}
		}),
	)
	const pools = (await Promise.all(adminUrls.map(async url => (await fetch(`${url}/pools`)).json()))).map(list => ({
		pools: list.length,
		servers: list.reduce((n, pool) => n + pool.servers_active + pool.servers_idle, 0),
	}))
	return { logins: percentiles(latencies), errors, mismatches, pools }
}

/** Cumulative lokaj pool waits per histogram bucket bound, summed over pools and replicas. */
async function poolWaits() {
	const totals = {}
	for (const url of adminUrls) {
		const text = await (await fetch(`${url}/metrics`)).text()
		for (const line of text.split('\n')) {
			const match = line.match(/^lokaj_pool_wait_seconds_bucket\{.*\ble="([^"]+)".*\} (\S+)$/)
			if (match) {
				const bound = match[1] === '+Inf' ? 'Infinity' : String(Number(match[1]))
				totals[bound] = (totals[bound] ?? 0) + Number(match[2])
			}
		}
	}
	return totals
}

/** Selected lokaj counters, summed over the replicas. */
async function lokajCounters() {
	const totals = {}
	for (const url of adminUrls) {
		const text = await (await fetch(`${url}/metrics`)).text()
		for (const line of text.split('\n')) {
			const match = line.match(/^(lokaj_(?:server_connects|server_connect_errors|server_recycles|auth_failures|credential_cache|dns_changes|cancels)_total)(\{[^}]*\})? (\S+)$/)
			if (match) totals[`${match[1]}${match[2] ?? ''}`] = (totals[`${match[1]}${match[2] ?? ''}`] ?? 0) + Number(match[3])
		}
	}
	return totals
}

const ms = value => (Number.isNaN(value) ? '-' : value.toFixed(2))
function print(result) {
	log(`${result.name}: ${result.txPerSecond.toFixed(0)} tx/s over ${result.seconds.toFixed(0)} s`)
	log(`  transaction ms  p50 ${ms(result.tx.p50)}  p99 ${ms(result.tx.p99)}  p99.9 ${ms(result.tx.p999)}  max ${ms(result.tx.max)}`)
	log(`  pool acquire ms p50 ${ms(result.acquire.p50)}  p99 ${ms(result.acquire.p99)};  new client login ms p50 ${ms(result.logins.p50)}  p99 ${ms(result.logins.p99)} (n=${result.logins.n})`)
	log(`  backends max ${result.backends.max} avg ${result.backends.avg.toFixed(1)};  new backends ${result.newBackendsPerSecond.toFixed(2)}/s;  lokaj assigned max ${result.backends.assignedMax}`)
	log(`  generator cpu ${result.generatorCpu.toFixed(2)} threads;  worker loop delay ms p99 ${ms(result.loop.p99)} max ${ms(result.loop.max)}`)
	log(`  errors ${JSON.stringify(result.errors)}  tenant mismatches ${result.mismatches}`)
	if (result.slow.length) {
		const count = keys => keys.reduce((counts, key) => ({ ...counts, [key]: (counts[key] ?? 0) + 1 }), {})
		const slowest = count(result.slow.map(({ steps }) => STEPS[steps.indexOf(Math.max(...steps))]))
		const seconds = Object.entries(count(result.slow.map(({ at }) => Math.floor(at / 1000))))
			.sort((a, b) => b[1] - a[1])
		log(`  slow transactions ${result.slow.length}: slowest step ${JSON.stringify(slowest)};  by port ${JSON.stringify(count(result.slow.map(s => s.port)))}`)
		log(`    in ${seconds.length} distinct seconds, busiest: ${seconds.slice(0, 5).map(([at, n]) => `${new Date(at * 1000).toISOString().slice(11, 19)} ${n}`).join(', ')}`)
	}
	const waits = result.waits.Infinity ?? 0
	if (waits) {
		const over = bound => waits - (result.waits[String(bound)] ?? 0)
		log(`  lokaj pool waits ${waits};  over 1 ms ${over(0.001)}, 10 ms ${over(0.01)}, 100 ms ${over(0.1)}`)
	}
}

async function main() {
	const { root, tenants } = await setup()
	const workers = plan(tenants).map(workerData => new Worker(new URL('./load-worker.mjs', import.meta.url), { workerData }))
	const results = {}
	try {
		log('phase: direct to PostgreSQL')
		await phase(direct, workers)
		results.direct = await window('direct', root, workers, DURATION)
		await stop(workers)
		print(results.direct)
		await sleep(2000)

		log(`phase: through ${POOLER}`)
		// Opened before the warm-up: its logins briefly stall the server, and pools that grew
		// during a stall keep their connections for the server idle timeout.
		const probe = await openProbe(tenants.slice(0, HOT.length + WARM.projects))
		await phase(viaLokaj, workers)
		results.lokaj = await window(POOLER, root, workers, DURATION, () => probe.run(DURATION))
		await probe.close()
		print(results.lokaj)
		log(`  ${POOLER} cpu ${results.lokaj.lokajCpu.map(cpu => `${(cpu * 100).toFixed(0)} %`).join(', ')};  rss MiB ${results.lokaj.lokajMemory.map(m => m.rss.toFixed(0)).join(', ')}`)
		const { direct: pd, tls: pt, lokaj: pl } = results.lokaj.extra
		log(`  probe ms (n=${pd.n})  direct p50 ${ms(pd.p50)} p99 ${ms(pd.p99)}  direct TLS p50 ${ms(pt.p50)} p99 ${ms(pt.p99)}  ${POOLER} p50 ${ms(pl.p50)} p99 ${ms(pl.p99)}`)
		log(`  ${POOLER} over direct TLS: p50 +${ms(pl.p50 - pt.p50)} p99 +${ms(pl.p99 - pt.p99)}`)

		log(`phase: login sweep over ${TENANTS} projects under load`)
		results.sweep = await window(`${POOLER} during the sweep`, root, workers, 0, () => sweep(tenants))
		await stop(workers)
		print(results.sweep)
		const { extra } = results.sweep
		log(`  sweep logins ms p50 ${ms(extra.logins.p50)} p99 ${ms(extra.logins.p99)} (n=${extra.logins.n})  errors ${JSON.stringify(extra.errors)}  mismatches ${extra.mismatches}`)
		log(`  per replica after the sweep: ${JSON.stringify(extra.pools)};  peak rss MiB ${results.sweep.lokajMemory.map(m => m.peak.toFixed(0)).join(', ')}`)
		log(`  counters ${JSON.stringify(await lokajCounters())}`)
	} finally {
		await Promise.all(workers.map(worker => worker.terminate()))
		await root.end()
	}

	const { direct: d, lokaj: l, sweep: s } = results
	const checks = [
		['reader backends', l.backends.max, CRITERIA.backends, `≤ ${CRITERIA.backends}`],
		['new backends/s', l.newBackendsPerSecond, CRITERIA.newBackendsPerSecond, `≤ ${CRITERIA.newBackendsPerSecond}`],
		['added p50 ms', l.extra.lokaj.p50 - l.extra.direct.p50, CRITERIA.addedP50, `≤ ${CRITERIA.addedP50}`],
		['added p99 ms', l.extra.lokaj.p99 - l.extra.direct.p99, CRITERIA.addedP99, `≤ ${CRITERIA.addedP99}`],
		[`${POOLER} peak rss MiB`, Math.max(...s.lokajMemory.map(m => m.peak)), CRITERIA.rssMiB, `≤ ${CRITERIA.rssMiB}`],
		['errors', [d.errors, l.errors, s.errors, s.extra.errors].flatMap(Object.values).reduce((a, b) => a + b, 0), 0, '= 0'],
		['tenant mismatches', d.mismatches + l.mismatches + l.extra.mismatches + s.mismatches + s.extra.mismatches, 0, '= 0'],
	]
	console.log('\nacceptance')
	for (const [name, value, limit, rule] of checks) {
		const ok = value <= limit
		if (!ok) process.exitCode = 1
		console.log(`  ${ok ? 'pass' : 'FAIL'}  ${name.padEnd(20)} ${(Number.isInteger(value) ? String(value) : value.toFixed(2)).padStart(8)}  ${rule}`)
	}
}

main().catch(error => {
	console.error(error)
	process.exitCode = 1
})
