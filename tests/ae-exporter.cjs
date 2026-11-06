// Adapter contract checks with an AE mock. This is NOT an After Effects runtime test.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const path = require('path');
const code = fs.readFileSync(path.join(__dirname, '..', 'Adobe', 'Export-AfterEffects-Dependencies.jsx'), 'utf8');
function run({ saved = true, cancel = false, exists = false, confirm = true } = {}) {
  let contents = '', writes = 0;
  const alerts = [];
  function File(p) { this.fsName = p; this.name = p.split('/').pop(); this.exists = exists; }
  File.prototype.saveDlg = function () { return cancel ? null : this; };
  File.prototype.open = function () { return true; };
  File.prototype.write = function (s) { contents = s; writes++; return true; };
  File.prototype.close = function () {};
  function FootageItem(p, proxy, missing) { this.file = p ? new File(p) : null; this.proxySource = proxy ? { file: new File(proxy) } : null; this.footageMissing = missing; this.name = 'item <&"'; }
  const items = [new FootageItem('D:/Кадры/A & B.mov', 'D:/proxy.mov', false), new FootageItem('D:/Кадры/A & B.mov', null, true), {}];
  const context = { File, FootageItem, app: { project: { file: saved ? new File('D:/edit.aep') : null, numItems: items.length, item: i => items[i - 1] } }, alert: s => alerts.push(s), confirm: () => confirm };
  vm.runInNewContext(code, context, { timeout: 2000 });
  return { contents, writes, alerts };
}
let result = run();
assert.equal(result.writes, 1);
assert(result.contents.includes('D:/Кадры/A &amp; B.mov'));
assert.equal((result.contents.match(/role="footage"/g) || []).length, 1);
assert(result.contents.includes('role="proxy"'));
assert(result.contents.includes('Missing footage: item &lt;&amp;&quot;'));
assert.equal(run({ saved: false }).writes, 0);
assert.equal(run({ cancel: true }).writes, 0);
assert.equal(run({ exists: true, confirm: false }).writes, 0);
fs.writeFileSync(path.join(__dirname, 'ae-exporter-tests.json'), JSON.stringify({ status: 'PASS', checks: ['footage and proxy', 'XML escaping and Unicode', 'deduplication', 'missing footage warning', 'unsaved project', 'cancelled save', 'declined overwrite'], nativeAdobeRuntimeTested: false }, null, 2));
console.log('AE exporter contract: 7 checks PASS; native Adobe runtime NOT tested');
