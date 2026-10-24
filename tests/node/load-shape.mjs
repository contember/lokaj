// The transaction every load-test client runs, shaped like the engine's read path.

const ARTICLES = `select a.id, a.title, a.published_at, au.name as author
	from article a join author au on au.id = a.author_id
	where a.views > $1 order by a.published_at desc limit $2`
const BY_AUTHOR = 'select current_database() as db, count(*)::int as n, max(views) as views from article where author_id = $1'

export const STEPS = ['begin', 'set', 'listing', 'aggregate', 'commit']

/**
 * BEGIN, REPEATABLE READ, a listing and an aggregate; resolves to the database that answered.
 * `steps` receives the duration of each statement in ms, in the order of `STEPS`.
 */
export async function readTransaction(client, steps = []) {
	const step = async (text, values) => {
		const start = performance.now()
		const result = await client.query(text, values)
		steps.push(performance.now() - start)
		return result
	}
	await step('BEGIN', [])
	await step('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
	await step(ARTICLES, [Math.floor(Math.random() * 1000), 25])
	const aggregate = await step(BY_AUTHOR, [1 + Math.floor(Math.random() * 20)])
	await step('COMMIT')
	return aggregate.rows[0].db
}
