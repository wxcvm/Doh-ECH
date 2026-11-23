import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../_worker.js', import.meta.url), 'utf8');
const start = source.indexOf('function isUsableDnsJson(');
const end = source.indexOf('\n/**', start);
assert.ok(start >= 0 && end > start);
const validate = vm.runInNewContext(source.slice(start, end) + '\nisUsableDnsJson');
const question = { name: 'www.example.com.', type: 65 };
const answer = (name, type, data) => ({ name, type, data, TTL: 60 });
const check = Answer => validate({ Status: 0, Question: [question], Answer }, 65, 'www.example.com');
assert.equal(check([answer('www.example.com.', 65, '1 . alpn=h2')]), true);
assert.equal(check([answer('unrelated.test.', 65, '1 . alpn=h2')]), false);
assert.equal(check([
  answer('www.example.com.', 5, 'edge.example.net.'),
  answer('edge.example.net.', 65, '1 . alpn=h2')
]), true);
assert.equal(check([
  answer('edge.example.net.', 65, '1 . alpn=h2'),
  answer('www.example.com.', 5, 'edge.example.net.')
]), true);
assert.equal(check([
  answer('www.example.com.', 5, 'edge.example.net.'),
  answer('other.test.', 65, '1 . alpn=h2')
]), false);
assert.equal(check([answer('www.example.com.', 5, 'www.example.com.')]), false);
assert.equal(validate({Status: 3, Question: [question]},65,'www.example.com'),true);
console.log('DNS JSON owner validation passed');
