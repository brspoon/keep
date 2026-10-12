const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('static/keep-api-reference.js', 'utf8');

function contract() {
  return {
    openapi: '3.1.0', info: {description: 'Keys are created in Admin. Scopes do not grant account permissions.'},
    servers: [{url: '/api/v1'}], 'x-scope-descriptions': {'keeps:write': 'Manage permitted Keep protection.'},
    components: {
      securitySchemes: {KeepBearer: {type: 'http', scheme: 'bearer', description: 'Use the API key in the Authorization header.'}},
      parameters: {
        KeepId: {name: 'keep_id', in: 'path', required: true, schema: {type: 'string', pattern: '^[0-9]+:[0-9]+$'}, example: '1:42'},
        Retry: {name: 'Idempotency-Key', in: 'header', required: true, description: 'Reuse this value only for the same request.', schema: {type: 'string', minLength: 16, maxLength: 128}, example: 'client-keep-create-0001'},
      },
      examples: {Indefinite: {summary: 'Indefinite protection', value: {duration: 'indefinite'}}},
      schemas: {
        Request: {type: 'object', additionalProperties: false, required: ['duration'], properties: {
          duration: {type: 'string', enum: ['temporary', 'indefinite'], default: 'temporary', description: 'Length of protection.'},
          days: {type: 'integer', minimum: 1, maximum: 365, default: 30},
        }},
        KeepBase: {type: 'object', required: ['duration'], properties: {duration: {type: 'string', enum: ['temporary', 'indefinite']}}},
        Keep: {allOf: [{$ref: '#/components/schemas/KeepBase'}, {type: 'object', required: ['expires_at'], properties: {
          expires_at: {type: ['string', 'null'], format: 'date-time', description: 'Null for indefinite protection.'},
          enabled: {type: 'boolean', default: false},
        }}]},
        Envelope: {type: 'object', required: ['data'], properties: {data: {$ref: '#/components/schemas/Keep'},
          paging: {type: 'object', required: ['next'], properties: {next: {anyOf: [{type: 'integer', minimum: 0}, {type: 'null'}]}}}}},
        'escaped/name~': {type: 'string', maxLength: 7},
      },
      responses: {Success: {description: 'Updated protection.', headers: {'Retry-After': {description: 'Wait this many seconds.', schema: {type: 'integer', minimum: 1}}},
        content: {'application/json': {schema: {$ref: '#/components/schemas/Envelope'}, examples: {
          Temporary: {summary: 'Temporary response', value: {data: {duration: 'temporary', expires_at: '2026-11-01T12:00:00Z'}}},
          Indefinite: {summary: 'Indefinite response', value: {data: {duration: 'indefinite', expires_at: null}}},
        }}}}},
    },
    paths: {'/keeps/{keep_id}': {
      parameters: [{$ref: '#/components/parameters/KeepId'}, {name: 'limit', in: 'query', description: 'Page size.', schema: {type: 'integer', minimum: 1, maximum: 100, default: 25}}],
      patch: {summary: 'Change protection', description: 'Change a Keep duration.', 'x-required-scope': 'keeps:write',
        parameters: [{$ref: '#/components/parameters/Retry'}],
        requestBody: {required: true, content: {'application/json': {schema: {$ref: '#/components/schemas/Request'}, examples: {
          Temporary: {summary: 'Temporary protection', description: 'Extend a temporary Keep.', value: {duration: 'temporary'}},
          Indefinite: {$ref: '#/components/examples/Indefinite'},
        }}}}, responses: {'200': {$ref: '#/components/responses/Success'}, '204': {description: 'No content.'}},
      },
    }},
  };
}

function fixture(spec = contract(), options = {}) {
  let document;
  class Element {
    constructor(tag = 'div', text = '') {
      this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.dataset = {}; this.listeners = {}; this.hidden = false; this._text = text; this.classes = new Set(); this.value = '';
      this.classList = {add: name => this.classes.add(name), remove: name => this.classes.delete(name), contains: name => this.classes.has(name)};
    }
    get className() { return [...this.classes].join(' '); }
    set className(value) { this.classes = new Set(value.split(/\s+/).filter(Boolean)); }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    set textContent(value) { this._text = String(value); this.children = []; }
    set innerHTML(_) { throw new Error('Reference text must not be parsed as HTML'); }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this._text = ''; this.children = children; }
    get lastChild() { return this.children.at(-1); }
    get childElementCount() { return this.children.filter(child => child.tagName !== '#TEXT').length; }
    setAttribute(name, value) { this.attrs[name] = String(value); }
    querySelectorAll(selector) {
      const matches = node => selector.startsWith('.') ? node.classes.has(selector.slice(1)) : node.tagName === selector.toUpperCase();
      return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
    async fire(type, extra = {}) { await Promise.all((this.listeners[type] || []).map(handler => handler({target: this, ...extra}))); }
    focus(options) { document.activeElement = this; this.focusOptions = options; }
  }
  document = new Element('document');
  const ids = Object.fromEntries(['api-operation-list', 'api-load-status', 'api-load-retry', 'api-contract-overview', 'api-search', 'api-search-clear', 'api-search-status', 'api-empty'].map(id => [id, new Element()]));
  ids['api-operation-list'].dataset.specUrl = '/static/openapi.json';
  ids['api-load-retry'].hidden = true;
  document.getElementById = id => ids[id]; document.createElement = tag => new Element(tag); document.createTextNode = text => new Element('#text', text);
  document.append(...Object.values(ids));
  const window = new Element('window');
  const calls = [], copies = [];
  let response = options.response || (() => ({ok: true, json: async () => spec}));
  const fetch = async (url, init) => { calls.push({url, init}); return response(); };
  const navigator = options.clipboard === false ? {} : {clipboard: {writeText: async text => { if (options.clipboardFailure) throw new Error('Permission denied'); copies.push(text); }}};
  vm.runInNewContext(source, {document, window, fetch, navigator, location: {origin: 'https://keep.example'}, Error, encodeURIComponent});
  return {document, window, ids, calls, copies, setResponse: value => { response = value; }, settle: () => new Promise(resolve => setImmediate(resolve))};
}
const buttonNamed = (f, title) => f.document.querySelectorAll('button').find(button => button.attrs['aria-label'] === `Copy ${title}`);
const rowNamed = (table, name) => table.querySelectorAll('tr').find(row => row.children[0]?.textContent === name);

test('renders local references, nested response fields, required flags, nullability, defaults and constraints', async () => {
  const f = fixture(); await f.settle();
  assert.equal(f.ids['api-load-status'].hidden, true);
  const response = f.document.querySelectorAll('table').find(table => table.children[0].textContent.startsWith('200 response'));
  assert.ok(response);
  const expiry = rowNamed(response, 'data.expires_at');
  assert.match(expiry.children[1].textContent, /string or null \(date-time\)/);
  assert.equal(expiry.children[2].textContent, 'Yes');
  assert.match(expiry.children[3].textContent, /Null for indefinite/);
  assert.equal(rowNamed(response, 'data.duration').children[2].textContent, 'Yes');
  assert.match(rowNamed(response, 'data.enabled').textContent, /Default: false/);
  assert.match(rowNamed(response, 'paging.next').textContent, /integer or null/);
  assert.match(rowNamed(response, 'paging.next').textContent, /Minimum: 0/);
  const request = f.document.querySelectorAll('table')[0];
  assert.match(rowNamed(request, 'duration').textContent, /Length of protection.*Allowed: temporary, indefinite.*Default: temporary/);
  assert.match(rowNamed(request, 'days').textContent, /Minimum: 1.*Maximum: 365/);
  assert.match(rowNamed(request, '$').textContent, /No additional fields/);
  const parameters = f.document.querySelector('.api-parameter-list');
  assert.match(parameters.textContent, /Page size.*Default: 25.*Minimum: 1.*Maximum: 100/);
  assert.match(parameters.textContent, /Idempotency-Key.*required.*Minimum length: 16.*Maximum length: 128/);
  assert.match(f.document.textContent, /Retry-After.*Wait this many seconds.*Minimum: 1/);
  assert.match(f.document.textContent, /No response body/);
});

test('renders every named request and response example, their descriptions, and placeholder-only curl commands', async () => {
  const f = fixture(); await f.settle();
  for (const title of ['Temporary protection', 'Indefinite protection', 'Temporary response', 'Indefinite response', 'curl · Temporary protection', 'curl · Indefinite protection']) assert.ok(buttonNamed(f, title), title);
  assert.match(f.document.textContent, /Extend a temporary Keep/);
  await buttonNamed(f, 'curl · Indefinite protection').fire('click');
  const curl = f.copies[0];
  assert.match(curl, /curl --request PATCH 'https:\/\/keep.example\/api\/v1\/keeps\/1%3A42'/);
  assert.match(curl, /Authorization: Bearer YOUR_KEEP_API_KEY/);
  assert.match(curl, /Idempotency-Key: client-keep-create-0001/);
  assert.match(curl, /--data '\{"duration":"indefinite"\}'/);
  assert.equal(f.calls.length, 1, 'copying must not send any API request');
  assert.equal(f.calls[0].url, '/static/openapi.json');
  assert.equal(f.calls[0].init.credentials, 'same-origin');
  assert.deepEqual(Object.keys(f.calls[0].init.headers), ['Accept']);
});

test('keeps quick start concise and shows the authorization header and every required scope', async () => {
  const f = fixture(); await f.settle();
  const text = f.ids['api-contract-overview'].textContent;
  assert.doesNotMatch(text, /Keys are created in Admin|Scopes do not grant|Use the API key in the Authorization header/);
  assert.match(text, /Authorization: Bearer YOUR_KEEP_API_KEY/);
  assert.match(text, /Replace YOUR_KEEP_API_KEY with your key/);
  assert.match(text, /keeps:write.*Manage permitted Keep protection/);
  assert.equal(f.ids['api-contract-overview'].hidden, false);
});

test('renders hostile contract strings as text and shell-quotes hostile JSON examples', async () => {
  const spec = contract();
  const hostile = '<img src=x onerror=alert(1)>\'$(touch /tmp/never-executed)';
  spec.paths['/keeps/{keep_id}'].patch.summary = hostile;
  spec.paths['/keeps/{keep_id}'].patch.requestBody.content['application/json'].examples.Temporary.value = {duration: hostile};
  const f = fixture(spec); await f.settle();
  assert.equal(f.ids['api-load-status'].hidden, true);
  assert.match(f.document.textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(f.document.querySelectorAll('img').length, 0);
  await buttonNamed(f, 'curl · Temporary protection').fire('click');
  assert.ok(f.copies[0].includes(`'"'"'$(touch /tmp/never-executed)`));
  assert.equal(f.calls.length, 1);
});

test('clipboard success is announced; missing or denied clipboard focuses selectable code', async () => {
  for (const options of [{}, {clipboard: false}, {clipboardFailure: true}]) {
    const f = fixture(contract(), options); await f.settle();
    const button = buttonNamed(f, 'Temporary protection'); await button.fire('click');
    const figure = f.document.querySelectorAll('figure').find(node => node.querySelector('button') === button);
    if (options.clipboard === false || options.clipboardFailure) {
      assert.equal(f.document.activeElement, figure.querySelector('pre'));
      assert.match(figure.textContent, /Clipboard unavailable.*copy it manually/);
    } else {
      assert.equal(f.copies[0], '{\n  "duration": "temporary"\n}');
      assert.match(figure.querySelector('.api-copy-status').textContent, /^Copied\.$/);
    }
    assert.equal(figure.querySelector('pre').tabIndex, 0);
    assert.equal(figure.querySelector('.api-copy-status').attrs.role, 'status');
    assert.equal(f.calls.length, 1);
  }
});

test('search matches parameters, reports results, and clear restores focus and endpoints', async () => {
  const f = fixture(); await f.settle();
  const search = f.ids['api-search'], operation = f.document.querySelector('.api-operation');
  search.value = 'Idempotency-Key'; await search.fire('input');
  assert.equal(operation.hidden, false);
  assert.equal(f.ids['api-search-status'].textContent, '1 endpoint found');
  search.value = 'absent endpoint'; await search.fire('input');
  assert.equal(operation.hidden, true); assert.equal(f.ids['api-empty'].hidden, false);
  await f.ids['api-search-clear'].fire('click');
  assert.equal(search.value, ''); assert.equal(operation.hidden, false); assert.equal(f.document.activeElement, search);
  assert.equal(search.focusOptions.preventScroll, true);
  assert.equal(f.ids['api-search-status'].textContent, '1 endpoint');
  search.value = '   '; await f.window.fire('pageshow');
  assert.equal(f.ids['api-search-clear'].hidden, false, 'whitespace must remain clearable');
  assert.equal(operation.hidden, false);
  search.value = 'restored missing query'; await f.window.fire('pageshow');
  assert.equal(operation.hidden, true, 'history restoration must reapply filtering');
  assert.equal(f.ids['api-empty'].hidden, false);
});

test('failed fetch, JSON decode, or invalid specification remains readable and can be retried', async () => {
  for (const response of [() => { throw new Error('offline'); }, () => ({ok: false}), () => ({ok: true, json: async () => { throw new Error('invalid JSON'); }}), () => ({ok: true, json: async () => ({openapi: '3.0.0', paths: {}})})]) {
    const f = fixture(contract(), {response}); await f.settle();
    assert.equal(f.ids['api-load-status'].hidden, false);
    assert.match(f.ids['api-load-status'].textContent, /Try again or download/);
    assert.equal(f.ids['api-load-retry'].hidden, false);
    f.setResponse(() => ({ok: true, json: async () => contract()}));
    await f.ids['api-load-retry'].fire('click');
    assert.equal(f.ids['api-load-status'].hidden, true);
    assert.equal(f.ids['api-load-retry'].hidden, true);
    assert.equal(f.ids['api-load-status'].classList.contains('api-load-error'), false);
    assert.equal(f.document.querySelectorAll('.api-operation').length, 1);
  }
});

test('recursive, unresolved, external and escaped local references do not hang or trigger extra fetches', async () => {
  const spec = contract();
  spec.components.schemas.Recursive = {type: 'object', properties: {child: {$ref: '#/components/schemas/Recursive'}}};
  spec.components.schemas.UnionCycle = {anyOf: [{$ref: '#/components/schemas/UnionCycle'}, {type: 'null'}]};
  const properties = spec.components.schemas.Request.properties;
  properties.recursive = {$ref: '#/components/schemas/Recursive'};
  properties.unionCycle = {$ref: '#/components/schemas/UnionCycle'};
  properties.missing = {$ref: '#/components/schemas/Missing'};
  properties.external = {$ref: 'https://outside.example/schema.json'};
  properties.escaped = {$ref: '#/components/schemas/escaped~1name~0'};
  const f = fixture(spec); await f.settle();
  assert.equal(f.ids['api-load-status'].hidden, true);
  assert.match(f.document.textContent, /Nested fields continue/);
  assert.match(f.document.textContent, /Unresolved reference/);
  assert.match(f.document.textContent, /External reference/);
  assert.match(f.document.textContent, /UnionCycle \(recursive\)/);
  assert.match(f.document.textContent, /Maximum length: 7/);
  assert.equal(f.calls.length, 1);
});

test('renders the checked-in contract and template exposes downloadable spec with concise guidance', async () => {
  const spec = JSON.parse(fs.readFileSync('static/openapi.json', 'utf8'));
  const f = fixture(spec); await f.settle();
  const count = Object.values(spec.paths).reduce((total, path) => total + ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'].filter(method => path[method]).length, 0);
  assert.equal(f.ids['api-load-status'].hidden, true);
  assert.equal(f.document.querySelectorAll('.api-operation').length, count);
  assert.ok(f.document.querySelectorAll('table').length > count);
  const template = fs.readFileSync('templates/api_reference.html', 'utf8');
  assert.match(template, /href="\/static\/openapi.json" download="keep-openapi.json"/);
  assert.match(template, /OpenAPI file for integration tools/);
  assert.match(template, />Download API definition<\/a>/);
  assert.ok(template.indexOf('api-resources-title') > template.indexOf('id="api-operation-list"'));
  assert.match(template, /Create a key in API keys and choose the scopes your integration needs/);
  assert.doesNotMatch(template, /href="\/settings\/api-keys"|api-actions|api-create-key/);
  assert.doesNotMatch(template, /<p>[^<]*<a/);
  assert.doesNotMatch(template, /browser session|credential store|separate bearer/);
});
