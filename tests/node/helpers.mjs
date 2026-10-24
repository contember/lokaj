// Shared setup for the node-pg suite: a direct superuser connection, per-test tenants with a
// content schema, and pools that connect through lokaj the way the engine does.
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import pg from 'pg'

const [lokajHost, lokajPort] = process.env.LOKAJ_TEST_LOKAJ.split(':')
const [pgHost, pgPort] = process.env.LOKAJ_TEST_PG.split(':')
export const adminUrl = `http://${process.env.LOKAJ_TEST_ADMIN}`
const ca = readFileSync(process.env.LOKAJ_TEST_CA, 'utf8')

export const admin = (database = 'postgres') =>
	new pg.Client({ host: pgHost, port: Number(pgPort), user: 'postgres', password: 'postgres', database })

export const lokajConfig = (tenant, extra = {}) => ({
	host: lokajHost,
	port: Number(lokajPort),
	user: tenant.user,
	password: tenant.password,
	database: tenant.database,
	ssl: { ca, servername: 'localhost' },
	...extra,
})

export const lokajPool = (tenant, extra = {}) => new pg.Pool({ max: 5, ...lokajConfig(tenant, extra) })

/** A role owning a database with the schemas and tables of a small content project. */
export async function createTenant() {
	const name = `n_${randomBytes(6).toString('hex')}`
	const tenant = { user: name, database: name, password: randomBytes(12).toString('base64url') }
	const root = admin()
	await root.connect()
	try {
		await root.query(`CREATE ROLE "${name}" LOGIN PASSWORD '${tenant.password}'`)
		await root.query(`CREATE DATABASE "${name}" OWNER "${name}"`)
		await root.query(`REVOKE CONNECT ON DATABASE "${name}" FROM PUBLIC`)
	} finally {
		await root.end()
	}
	const owner = new pg.Client({ host: pgHost, port: Number(pgPort), ...tenant })
	await owner.connect()
	try {
		await owner.query(`
			CREATE SCHEMA system;
			CREATE TABLE system.stage (id uuid PRIMARY KEY, slug text NOT NULL, name text NOT NULL);
			CREATE TABLE system.schema_migration (version text PRIMARY KEY, executed_at timestamptz NOT NULL DEFAULT now());
			INSERT INTO system.stage VALUES ('00000000-0000-0000-0000-000000000001', 'live', 'Live');
			INSERT INTO system.schema_migration (version) SELECT '2026-01-01-' || lpad(g::text, 6, '0') FROM generate_series(1, 50) g;
			CREATE SCHEMA stage_live;
			CREATE TABLE stage_live.author (id uuid PRIMARY KEY, name text NOT NULL);
			CREATE TABLE stage_live.article (
				id uuid PRIMARY KEY, author_id uuid REFERENCES stage_live.author, title text NOT NULL,
				published_at timestamptz, body jsonb NOT NULL, views bigint NOT NULL DEFAULT 0, score numeric(10, 2)
			);
			CREATE TABLE stage_live.tag (id uuid PRIMARY KEY, label text NOT NULL);
			CREATE TABLE stage_live.article_tags (article_id uuid REFERENCES stage_live.article, tag_id uuid REFERENCES stage_live.tag, PRIMARY KEY (article_id, tag_id));
			INSERT INTO stage_live.author SELECT gen_random_uuid(), 'Author ' || g FROM generate_series(1, 20) g;
			INSERT INTO stage_live.tag SELECT gen_random_uuid(), 'tag-' || g FROM generate_series(1, 30) g;
			INSERT INTO stage_live.article
				SELECT gen_random_uuid(), (SELECT id FROM stage_live.author ORDER BY id OFFSET g % 20 LIMIT 1), 'Article ' || g,
					now() - g * interval '1 hour', jsonb_build_object('blocks', jsonb_build_array(jsonb_build_object('type', 'p', 'text', repeat('lorem ', 50)))),
					g * 10, g / 3.0
				FROM generate_series(1, 500) g;
			INSERT INTO stage_live.article_tags
				SELECT a.id, t.id FROM stage_live.article a CROSS JOIN LATERAL (SELECT id FROM stage_live.tag ORDER BY random() LIMIT 3) t;
		`)
	} finally {
		await owner.end()
	}
	return tenant
}

export async function poolStats() {
	const response = await fetch(`${adminUrl}/pools`)
	return response.json()
}
