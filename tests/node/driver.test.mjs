// node-pg (the engine's driver version) through lokaj: connection setup, read transactions in the
// shapes the engine issues, and pooling behaviour under concurrency and connection churn.
import assert from 'node:assert/strict'
import { after, before, describe, test } from 'node:test'
import pg from 'pg'
import { admin, createTenant, lokajConfig, lokajPool, poolStats } from './helpers.mjs'

const REPEATABLE_READ = 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ'

/** Runs `callback` in a transaction the way the engine's read path does. */
async function readTransaction(pool, callback) {
	const client = await pool.connect()
	try {
		await client.query('BEGIN', [])
		await client.query(REPEATABLE_READ)
		const result = await callback(client)
		await client.query('COMMIT')
		return result
	} catch (error) {
		await client.query('ROLLBACK').catch(() => {})
		throw error
	} finally {
		client.release()
	}
}

describe('connection setup', () => {
	let tenant
	before(async () => {
		tenant = await createTenant()
	})

	test('connects over TLS and runs simple and parameterized queries', async () => {
		const client = new pg.Client(lokajConfig(tenant, { application_name: 'engine-test' }))
		await client.connect()
		try {
			const simple = await client.query('select current_user, current_database(), current_setting(\'application_name\') as app')
			assert.equal(simple.rows[0].current_user, tenant.user)
			assert.equal(simple.rows[0].current_database, tenant.database)
			const typed = await client.query(
				'select $1::int as i, $2::text as t, $3::jsonb as j, $4::uuid as u, $5::timestamptz as ts, $6::numeric as n, $7::bytea as b, $8::text[] as a',
				[42, 'žluťoučký kůň', { a: [1, 2] }, '6ba7b810-9dad-11d1-80b4-00c04fd430c8', new Date('2026-01-02T03:04:05Z'), '12.50', Buffer.from([0, 1, 255]), ['x', 'y']],
			)
			const row = typed.rows[0]
			assert.equal(row.i, 42)
			assert.equal(row.t, 'žluťoučký kůň')
			assert.deepEqual(row.j, { a: [1, 2] })
			assert.equal(row.u, '6ba7b810-9dad-11d1-80b4-00c04fd430c8')
			assert.equal(row.ts.toISOString(), '2026-01-02T03:04:05.000Z')
			assert.equal(row.n, '12.50')
			assert.deepEqual([...row.b], [0, 1, 255])
			assert.deepEqual(row.a, ['x', 'y'])
		} finally {
			await client.end()
		}
	})

	test('refuses clients without TLS', async () => {
		const client = new pg.Client(lokajConfig(tenant, { ssl: false }))
		await assert.rejects(client.connect(), { code: '28000' })
	})

	test('refuses a wrong password with 28P01', async () => {
		const client = new pg.Client(lokajConfig(tenant, { password: 'nope' }))
		await assert.rejects(client.connect(), { code: '28P01' })
	})

	test('statement and lock timeouts from the client config apply', async () => {
		const client = new pg.Client(lokajConfig(tenant, { statement_timeout: 200, lock_timeout: 100 }))
		await client.connect()
		try {
			await assert.rejects(client.query('select pg_sleep(2)'), { code: '57014' })
			const settings = await client.query("select current_setting('lock_timeout') as lock")
			assert.equal(settings.rows[0].lock, '100ms')
		} finally {
			await client.end()
		}
	})

	test('session-level SET is refused and ends the client', async () => {
		const client = new pg.Client(lokajConfig(tenant))
		client.on('error', () => {})
		await client.connect()
		await assert.rejects(client.query('SET search_path TO stage_live'), { code: '0A000' })
		await client.end().catch(() => {})
	})
})

describe('engine read path', () => {
	let tenant
	let pool
	before(async () => {
		tenant = await createTenant()
		pool = lokajPool(tenant)
	})
	after(async () => {
		await pool.end()
	})

	test('content, system and tenant-style reads in repeatable read transactions', async () => {
		const result = await readTransaction(pool, async client => {
			const stage = await client.query('select "id", "slug", "name" from "system"."stage" where "slug" = $1', ['live'])
			const migrations = await client.query('select "version" from "system"."schema_migration" order by "version" desc limit $1', [5])
			const articles = await client.query(
				`select "root_"."id" as "root_id", "root_"."title" as "root_title", "root_"."published_at" as "root_publishedAt",
					"root_"."body" as "root_body", "root_author"."name" as "root_author_name"
				from "stage_live"."article" as "root_"
				left join "stage_live"."author" as "root_author" on "root_"."author_id" = "root_author"."id"
				where "root_"."views" > $1 and "root_"."published_at" < $2
				order by "root_"."published_at" desc, "root_"."id" asc
				limit $3 offset $4`,
				[100, new Date(), 25, 0],
			)
			const ids = articles.rows.map(row => row.root_id)
			const tags = await client.query(
				`select "junction_"."article_id" as "__owning", "root_"."id" as "root_id", "root_"."label" as "root_label"
				from "stage_live"."article_tags" as "junction_"
				inner join "stage_live"."tag" as "root_" on "junction_"."tag_id" = "root_"."id"
				where "junction_"."article_id" in (select unnest($1::uuid[]))`,
				[ids],
			)
			const aggregate = await client.query(
				`with "counts" as (select "author_id", count(*) as "articles", sum("views") as "views" from "stage_live"."article" group by "author_id")
				select json_agg(json_build_object('author', a.name, 'articles', c.articles, 'views', c.views) order by a.name) as "data"
				from "counts" c join "stage_live"."author" a on a.id = c.author_id`,
			)
			return { stage, migrations, articles, tags, aggregate }
		})
		assert.equal(result.stage.rows[0].slug, 'live')
		assert.equal(result.migrations.rows.length, 5)
		assert.equal(result.articles.rows.length, 25)
		assert.equal(result.tags.rows.length, 75)
		assert.equal(result.aggregate.rows[0].data.length, 20)
	})

	test('a repeatable read transaction keeps its snapshot', async () => {
		const writer = admin(tenant.database)
		await writer.connect()
		try {
			await readTransaction(pool, async client => {
				const before = await client.query('select count(*)::int as n from "stage_live"."author"')
				await writer.query(`insert into "stage_live"."author" values (gen_random_uuid(), 'Late author')`)
				const during = await client.query('select count(*)::int as n from "stage_live"."author"')
				assert.equal(during.rows[0].n, before.rows[0].n)
			})
			const after = await pool.query('select count(*)::int as n from "stage_live"."author"')
			assert.equal(after.rows[0].n, 21)
		} finally {
			await writer.end()
		}
	})

	test('savepoints recover from errors inside a transaction', async () => {
		await readTransaction(pool, async client => {
			await client.query('SAVEPOINT "savepoint_0"')
			await assert.rejects(client.query('select $1::int / 0', [1]), { code: '22012' })
			await client.query('ROLLBACK TO SAVEPOINT "savepoint_0"')
			await client.query('SAVEPOINT "savepoint_1"')
			const ok = await client.query('select count(*)::int as n from "stage_live"."tag"')
			await client.query('RELEASE SAVEPOINT "savepoint_1"')
			assert.equal(ok.rows[0].n, 30)
		})
	})

	test('an error aborts the transaction until rollback, then the client is reusable', async () => {
		const client = await pool.connect()
		try {
			await client.query('BEGIN', [])
			await assert.rejects(client.query('select * from "stage_live"."missing"'), { code: '42P01' })
			await assert.rejects(client.query('select 1'), { code: '25P02' })
			await client.query('ROLLBACK')
			const ok = await client.query('select 1 as one')
			assert.equal(ok.rows[0].one, 1)
		} finally {
			client.release()
		}
	})

	test('large JSON results', async () => {
		const result = await pool.query(
			`select json_agg(json_build_object('id', id, 'title', title, 'body', body)) as "data" from "stage_live"."article"`,
		)
		assert.equal(result.rows[0].data.length, 500)
	})
})

describe('pooling', () => {
	let tenants
	before(async () => {
		tenants = await Promise.all(Array.from({ length: 10 }, () => createTenant()))
	})

	test('concurrent pools across databases see only their own data', async () => {
		const pools = tenants.map(tenant => lokajPool(tenant, { max: 8 }))
		try {
			await Promise.all(
				pools.map(async (pool, i) => {
					const queries = Array.from({ length: 150 }, (_, j) =>
						j % 3 === 0
							? readTransaction(pool, client => client.query('select current_database() as db, $1::int as j', [j]))
							: pool.query('select current_database() as db, $1::int as j', [j]),
					)
					for (const result of await Promise.all(queries)) {
						assert.equal(result.rows[0].db, tenants[i].database)
					}
				}),
			)
		} finally {
			await Promise.all(pools.map(pool => pool.end()))
		}
		for (const pool of await poolStats()) {
			assert.ok(pool.servers_active + pool.servers_idle <= 5, JSON.stringify(pool))
		}
	})

	test('client churn reuses a few server connections', async () => {
		const [tenant] = tenants
		const root = admin(tenant.database)
		await root.connect()
		try {
			const sessions = async () =>
				(await root.query('select count(*)::int as n from pg_stat_activity where usename = $1', [tenant.user])).rows[0].n
			// Waves stay under pool.max_waiters (100), past which lokaj refuses the query.
			for (let wave = 0; wave < 4; wave++) {
				await Promise.all(
					Array.from({ length: 50 }, async () => {
						const client = new pg.Client(lokajConfig(tenant))
						await client.connect()
						await client.query('select 1')
						await client.end()
					}),
				)
			}
			assert.ok((await sessions()) <= 5)
			const counted = await root.query('select sessions from pg_stat_database where datname = $1', [tenant.database])
			assert.ok(counted.rows[0].sessions <= 5 + 2, `server sessions: ${counted.rows[0].sessions}`)
		} finally {
			await root.end()
		}
	})
})
