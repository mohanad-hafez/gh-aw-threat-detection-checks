const assert = require('node:assert/strict');
const fs = require('node:fs');

const { inputs } = JSON.parse(fs.readFileSync('.github/matched/stats-fixture.json'));
const { stats, history, summary } = inputs;
assert.equal(history, null);
let decision;
if (process.env.ARM === 'agent') {
  const calls = fs.readFileSync('evidence/tools.jsonl', 'utf8').trim().split('\n').map(JSON.parse);
  assert(calls.every(call => !call.error));
  assert.equal(calls.at(-1).name, 'publish_result');
  decision = JSON.parse(calls.at(-1).args.body);
  if (decision.comparison && typeof decision.comparison === 'object') {
    assert.deepEqual(decision.comparison, { partial_day: true });
    decision.comparison = 'partial_day';
  }
} else {
  const result = JSON.parse(fs.readFileSync('evidence/go-result.json'));
  assert(result.body.includes("Today's collection covers a partial day; no like-for-like rate comparison is reported."));
  assert(result.body.includes('## Watch list\n\nNone\n'));
  assert(result.body.includes(summary));
  decision = { history: result.history, baseline: result.baseline, comparison: 'partial_day', watch: [] };
}
const expectedEntry = {
  date: stats.date, external_detector_runs: stats.totals.external_detector_runs,
  error_rate_pct: stats.error_rate_pct, soft_failures: stats.soft_failures.count,
  with_verdict: stats.detection_results.with_verdict, any_threat: stats.detection_results.any_threat,
  threat_rate_pct: stats.detection_results.threat_rate_pct, partial: stats.collection.rates_cover_partial_day,
};
assert.deepEqual(decision, { history: [expectedEntry], baseline: true, comparison: 'partial_day', watch: [] });
const report = {
  title: '[detection-stats] Detection stats for ' + stats.repository + ' - ' + stats.date,
  body: summary + '\n\nFirst saved day. Collection was partial, so there is no day-over-day comparison.\n' +
    'No watch-list entries were recorded in the available data.\n\n' +
    stats.collection.truncations.map(note => '- ' + note).join('\n'),
  labels: ['automation', 'detection-stats'],
};
fs.mkdirSync('stats-cache');
fs.writeFileSync('stats-cache/history.json', JSON.stringify([expectedEntry], null, 2) + '\n');
fs.writeFileSync('evidence/decision.json', JSON.stringify(decision));
fs.writeFileSync('evidence/result.json', JSON.stringify(report));

