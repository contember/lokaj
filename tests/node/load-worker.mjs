// One generator thread of the load test. It runs an open-loop (Poisson) schedule of engine-shaped
// read transactions over its share of pod pools, plus short-lived clients for connection churn
// and cold projects, and reports latencies and errors to the coordinator on every `mark`.
import { monitorEventLoopDelay } from 'node:perf_hooks'
import { parentPort, workerData } from 'node:worker_threads'
import pg from 'pg'
import { readTransaction } from './load-shape.mjs'

const { pods, churn, cold } = workerData

// A stalled event loop holds its server connections longer, so report how stalled it was.
const loop = monitorEventLoopDelay({ resolution: 5 })
loop.enable()

let stats = fresh()
function fresh() {
	return { tx: [], acquire: [], logins: [], errors: {}, mismatches: 0, slow: [] }
}
function fail(error) {
	const code = error.code ?? error.message
	stats.errors[code] = (stats.errors[code] ?? 0) + 1
}

let target
const connection = tenant => ({
	user: tenant.user,
	password: tenant.password,
	database: tenant.database,
	host: target.host,
	port: target.ports[Math.floor(Math.random() * target.ports.length)],
	ssl: target.ssl,
})

// Slow transactions are kept with their statement timings, to tell where a stall happened.
const SLOW_MS = 50

async function transaction(client, tenant) {
	const start = performance.now()
	const steps = []
	const database = await readTransaction(client, steps)
	const ms = performance.now() - start
	stats.tx.push(ms)
	if (ms > SLOW_MS) stats.slow.push({ at: Date.now(), port: client.port, steps })
	if (database !== tenant.database) stats.mismatches++
}

function poisson(rate, run) {
	let timer
	const tick = () => {
		run()
		timer = setTimeout(tick, (-Math.log(1 - Math.random()) * 1000) / rate)
	}
	timer = setTimeout(tick, (Math.random() * 1000) / rate)
	return () => clearTimeout(timer)
}

const inflight = new Set()
function track(promise) {
	inflight.add(promise)
	promise.finally(() => inflight.delete(promise))
}

let pools = []
let timers = []

function start() {
	stats = fresh()
	pools = pods.map(({ tenant, rate }) => {
		const pool = new pg.Pool({ max: 10, idleTimeoutMillis: 10_000, ...connection(tenant) })
		// Every new client picks a replica, as a Service spreads connections.
		Object.defineProperty(pool.options, 'port', { get: () => connection(tenant).port })
		pool.on('error', fail)
		pool.on('connect', client => client.on('error', () => {}))
		timers.push(poisson(rate, () => track(pooled(pool, tenant))))
		return pool
	})
	if (churn.rate > 0) timers.push(poisson(churn.rate, () => track(shortLived(pick(churn.tenants), 1))))
	if (cold.rate > 0) timers.push(poisson(cold.rate, () => track(shortLived(pick(cold.tenants), 3))))
}

const pick = list => list[Math.floor(Math.random() * list.length)]

async function pooled(pool, tenant) {
	const start = performance.now()
	let client
	try {
		client = await pool.connect()
		stats.acquire.push(performance.now() - start)
		await transaction(client, tenant)
		client.release()
	} catch (error) {
		fail(error)
		client?.release(true)
	}
}

async function shortLived(tenant, transactions) {
	const client = new pg.Client(connection(tenant))
	client.on('error', () => {})
	try {
		const start = performance.now()
		await client.connect()
		stats.logins.push(performance.now() - start)
		for (let i = 0; i < transactions; i++) await transaction(client, tenant)
	} catch (error) {
		fail(error)
	} finally {
		await client.end().catch(() => {})
	}
}

async function stop() {
	for (const clear of timers) clear()
	timers = []
	await Promise.all(inflight)
	await Promise.all(pools.map(pool => pool.end().catch(() => {})))
	pools = []
}

function take() {
	const taken = { ...stats, loopP99: loop.percentile(99) / 1e6, loopMax: loop.max / 1e6 }
	stats = fresh()
	loop.reset()
	return taken
}

parentPort.on('message', async message => {
	if (message.type === 'start') {
		target = message.target
		start()
		parentPort.postMessage({ type: 'started' })
	} else if (message.type === 'mark') {
		parentPort.postMessage({ type: 'stats', stats: take() })
	} else if (message.type === 'stop') {
		const taken = take()
		await stop()
		parentPort.postMessage({ type: 'stats', stats: taken })
	}
})
