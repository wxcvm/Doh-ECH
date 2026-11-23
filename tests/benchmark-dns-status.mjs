import assert from 'node:assert/strict';
import { isDnsProbeFailure } from '../scripts/dns-benchmark-status.mjs';
for (const rcode of [1, 2, 4, 5]) assert.equal(isDnsProbeFailure({rcode}), true, 'resolver failure '+rcode);
for (const rcode of [0, 3]) assert.equal(isDnsProbeFailure({rcode}), false, 'valid DNS outcome '+rcode);
assert.equal(isDnsProbeFailure({error: ''}), true, 'empty error is still a failure');
assert.equal(isDnsProbeFailure({error: 'timeout'}), true);
console.log('DNS benchmark response classification passed');
