/* Render the checked-in OpenAPI contract. Buttons copy examples; no API calls are executed. */
(() => {
  const list = document.getElementById('api-operation-list');
  const loadStatus = document.getElementById('api-load-status');
  const retry = document.getElementById('api-load-retry');
  const overview = document.getElementById('api-contract-overview');
  const search = document.getElementById('api-search');
  const clear = document.getElementById('api-search-clear');
  const searchStatus = document.getElementById('api-search-status');
  const empty = document.getElementById('api-empty');
  if (!list || !loadStatus) return;

  const element = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  };
  const valueText = value => typeof value === 'string' ? value : JSON.stringify(value);
  const resolveRef = (value, spec) => {
    const seen = new Set();
    while (value?.$ref) {
      const ref = value.$ref;
      if (!ref.startsWith('#/')) return {...value, description: 'External reference. Review the OpenAPI specification.'};
      if (seen.has(ref)) return {description: `Recursive reference: ${ref.split('/').pop()}`};
      seen.add(ref);
      const target = ref.slice(2).split('/').reduce((current, key) => current?.[key.replace(/~1/g, '/').replace(/~0/g, '~')], spec);
      if (!target || typeof target !== 'object') return {description: `Unresolved reference: ${ref}`};
      const {$ref, ...siblings} = value;
      value = {...target, ...siblings};
    }
    return value || {};
  };
  const schemaInfo = (raw, spec, seen = new Set()) => {
    const schema = resolveRef(raw, spec);
    const ref = raw?.$ref;
    if (ref && seen.has(ref)) return {description: `Recursive reference: ${ref.split('/').pop()}`};
    if (ref) seen = new Set([...seen, ref]);
    if (!schema.allOf) return schema;
    const parts = schema.allOf.map(part => schemaInfo(part, spec, seen));
    return {...Object.assign({}, ...parts), ...schema, properties: Object.assign({}, ...parts.map(part => part.properties || {}), schema.properties || {}),
      required: [...new Set([...parts.flatMap(part => part.required || []), ...(schema.required || [])])]};
  };
  const describeSchema = (raw, spec, seen = new Set(), depth = 0) => {
    if (depth >= 12 || (raw?.$ref && seen.has(raw.$ref))) return `${raw?.$ref?.split('/').pop() || 'value'} (recursive)`;
    const next = raw?.$ref ? new Set([...seen, raw.$ref]) : seen;
    const schema = schemaInfo(raw, spec);
    const variants = schema.oneOf || schema.anyOf;
    if (variants) return variants.map(variant => describeSchema(variant, spec, next, depth + 1)).join(schema.oneOf ? ' or (one of) ' : ' or ');
    const type = Array.isArray(schema.type) ? schema.type.join(' or ') : schema.type || (schema.properties ? 'object' : schema.items ? 'array' : 'value');
    return `${type}${schema.format ? ` (${schema.format})` : ''}${schema.nullable && !String(type).includes('null') ? ' or null' : ''}`;
  };
  const schemaNotes = (schema, spec, seen = new Set(), depth = 0) => {
    const notes = [];
    if (schema.description) notes.push(schema.description);
    if (schema.enum) notes.push(`Allowed: ${schema.enum.map(valueText).join(', ')}`);
    if (Object.hasOwn(schema, 'const')) notes.push(`Value: ${valueText(schema.const)}`);
    if (Object.hasOwn(schema, 'default')) notes.push(`Default: ${valueText(schema.default)}`);
    for (const [property, label] of [['minimum', 'Minimum'], ['maximum', 'Maximum'], ['exclusiveMinimum', 'Greater than'], ['exclusiveMaximum', 'Less than'], ['multipleOf', 'Multiple of'], ['minLength', 'Minimum length'], ['maxLength', 'Maximum length'], ['minItems', 'Minimum items'], ['maxItems', 'Maximum items'], ['minProperties', 'Minimum fields'], ['maxProperties', 'Maximum fields'], ['pattern', 'Pattern']]) {
      if (Object.hasOwn(schema, property)) notes.push(`${label}: ${schema[property]}`);
    }
    if (schema.uniqueItems) notes.push('Items must be unique');
    if (schema.additionalProperties === false) notes.push('No additional fields');
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object') notes.push(`Additional fields: ${describeSchema(schema.additionalProperties, spec)}`);
    if (schema.readOnly) notes.push('Read only');
    if (schema.writeOnly) notes.push('Write only');
    if (depth < 12) (schema.oneOf || schema.anyOf || []).forEach((variant, index) => {
      if (variant.$ref && seen.has(variant.$ref)) return;
      const next = variant.$ref ? new Set([...seen, variant.$ref]) : seen;
      const description = schemaNotes(schemaInfo(variant, spec), spec, next, depth + 1);
      if (description) notes.push(`Option ${index + 1}: ${description}`);
    });
    return notes.join(' · ');
  };
  const fieldTable = (raw, spec, label = 'Schema fields') => {
    const wrapper = element('div', 'api-table-scroll');
    wrapper.tabIndex = 0;
    wrapper.setAttribute('role', 'region');
    wrapper.setAttribute('aria-label', label);
    const table = element('table', 'api-field-table');
    const caption = element('caption', '', `${label}. Required means required within the containing object.`);
    caption.append(element('span', 'api-table-hint', ' Scroll horizontally for all columns.'));
    table.append(caption);
    const head = element('thead'), heading = element('tr');
    ['Field', 'Type', 'Required', 'Details'].forEach(title => {
      const cell = element('th', '', title); cell.setAttribute('scope', 'col'); heading.append(cell);
    });
    head.append(heading); table.append(head);
    const rows = element('tbody');
    const visit = (input, path, required, ancestors = new Set(), depth = 0) => {
      const schema = schemaInfo(input, spec);
      const row = element('tr'), name = element('th');
      name.setAttribute('scope', 'row'); name.append(element('code', '', path || '$'));
      row.append(name, element('td', 'api-field-type', describeSchema(input, spec)), element('td', '', required === undefined ? '—' : required ? 'Yes' : 'No'), element('td', '', schemaNotes(schema, spec)));
      rows.append(row);
      const ref = input?.$ref;
      if (depth >= 12 || (ref && ancestors.has(ref))) {
        row.lastChild.textContent = `${row.lastChild.textContent}${row.lastChild.textContent ? ' · ' : ''}Nested fields continue in the OpenAPI specification.`;
        return;
      }
      const next = ref ? new Set([...ancestors, ref]) : ancestors;
      Object.entries(schema.properties || {}).forEach(([name, child]) => visit(child, path ? `${path}.${name}` : name, (schema.required || []).includes(name), next, depth + 1));
      if (schema.items) visit(schema.items, `${path || '$'}[]`, undefined, next, depth + 1);
      const variants = schema.oneOf || schema.anyOf || [];
      variants.forEach((variant, index) => {
        const resolved = schemaInfo(variant, spec);
        if (resolved.properties || resolved.items) visit(variant, `${path || '$'} (option ${index + 1})`, undefined, next, depth + 1);
      });
    };
    visit(raw, '', undefined);
    table.append(rows); wrapper.append(table);
    return wrapper;
  };
  const addSection = (container, title, content) => {
    const section = element('section', 'api-detail-section');
    section.append(element('h4', '', title), content);
    container.append(section);
  };
  const codeExample = (title, value, description) => {
    const figure = element('figure', 'api-example');
    const caption = element('figcaption', 'api-example-heading');
    const button = element('button', 'api-copy', 'Copy');
    button.type = 'button'; button.setAttribute('aria-label', `Copy ${title}`);
    caption.append(element('span', '', title), button);
    figure.append(caption);
    if (description) figure.append(element('p', 'api-example-description', description));
    const pre = element('pre', 'api-code-example'); pre.tabIndex = 0;
    pre.setAttribute('aria-label', title); pre.append(element('code', '', value));
    const status = element('p', 'api-copy-status'); status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    button.addEventListener('click', async () => {
      try {
        if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
        await navigator.clipboard.writeText(value);
        status.textContent = 'Copied.';
      } catch (_) {
        // Keep the code focusable and selectable when the clipboard requires HTTPS or permission.
        pre.focus();
        status.textContent = 'Clipboard unavailable. Select the example and copy it manually.';
      }
    });
    figure.append(pre, status);
    return figure;
  };
  const examplesFor = (definition, spec) => {
    const examples = Object.entries(definition.examples || {}).map(([name, raw]) => ({name, ...resolveRef(raw, spec)}));
    if (Object.hasOwn(definition, 'example')) examples.push({name: 'Example', value: definition.example});
    return examples;
  };
  const renderContent = (container, content, spec, label) => {
    Object.entries(content || {}).forEach(([mediaType, definition]) => {
      container.append(element('p', 'api-media-type', mediaType));
      if (definition.schema) container.append(fieldTable(definition.schema, spec, `${label} fields (${mediaType})`));
      examplesFor(definition, spec).forEach(example => {
        if (Object.hasOwn(example, 'value')) container.append(codeExample(example.summary || example.name, typeof example.value === 'string' ? example.value : JSON.stringify(example.value, null, 2), example.description));
        else if (example.externalValue) container.append(element('p', 'api-example-description', `${example.summary || example.name}: external example at ${example.externalValue}`));
      });
    });
  };
  const parametersFor = (path, operation, spec) => {
    const parameters = new Map();
    [...(spec.paths[path].parameters || []), ...(operation.parameters || [])].forEach(raw => {
      const parameter = resolveRef(raw, spec);
      parameters.set(`${parameter.in}:${parameter.name}`, parameter);
    });
    return [...parameters.values()];
  };
  const parameterExample = (parameter, spec) => {
    const schema = schemaInfo(parameter.schema, spec);
    if (Object.hasOwn(parameter, 'example')) return parameter.example;
    const named = Object.values(parameter.examples || {}).map(raw => resolveRef(raw, spec)).find(value => Object.hasOwn(value, 'value'));
    if (named) return named.value;
    if (Object.hasOwn(schema, 'example')) return schema.example;
    if (schema.examples?.length) return schema.examples[0];
    if (Object.hasOwn(schema, 'default')) return schema.default;
    if (schema.enum?.length) return schema.enum[0];
    return parameter.name === 'Idempotency-Key' ? 'client-operation-0001' : `<${parameter.name}>`;
  };
  const shellQuote = value => `'${String(value).replace(/'/g, `'"'"'`)}'`;
  const curlExample = (path, method, operation, spec, body, mediaType) => {
    const parameters = parametersFor(path, operation, spec);
    let examplePath = path;
    parameters.filter(parameter => parameter.in === 'path').forEach(parameter => { examplePath = examplePath.replace(`{${parameter.name}}`, encodeURIComponent(parameterExample(parameter, spec))); });
    const query = parameters.filter(parameter => parameter.in === 'query' && parameter.required).map(parameter => `${encodeURIComponent(parameter.name)}=${encodeURIComponent(parameterExample(parameter, spec))}`).join('&');
    const base = spec.servers?.[0]?.url || '/api/v1';
    const origin = location.origin;
    const url = `${base.startsWith('/') ? origin : ''}${base.replace(/\/$/, '')}${examplePath}${query ? `?${query}` : ''}`;
    const lines = [`curl --request ${method.toUpperCase()} ${shellQuote(url)}`, `  --header ${shellQuote('Authorization: Bearer YOUR_KEEP_API_KEY')}`, `  --header ${shellQuote('Accept: application/json')}`];
    parameters.filter(parameter => parameter.in === 'header' && parameter.name.toLowerCase() !== 'authorization').forEach(parameter => lines.push(`  --header ${shellQuote(`${parameter.name}: ${parameterExample(parameter, spec)}`)}`));
    if (body !== undefined) lines.push(`  --header ${shellQuote(`Content-Type: ${mediaType}`)}`, `  --data ${shellQuote(typeof body === 'string' ? body : JSON.stringify(body))}`);
    return lines.join(' \\\n');
  };
  const renderOperation = (path, method, operation, spec) => {
    const details = element('details', 'api-operation');
    details.setAttribute('role', 'listitem');
    const summary = element('summary', 'api-operation-summary');
    const methodBadge = element('span', `api-method api-method-${method}`, method.toUpperCase());
    const pathText = element('code', 'api-path', (spec.servers?.[0]?.url || '/api/v1') + path);
    const summaryText = element('span', 'api-operation-title', operation.summary || operation.operationId || path);
    summary.append(methodBadge, pathText, summaryText); details.append(summary);
    const body = element('div', 'api-operation-body');
    if (operation.description) body.append(element('p', 'api-operation-description', operation.description));
    const scopes = operation['x-required-scope'];
    if (scopes) {
      const scopeLine = element('p', 'api-scope-line');
      scopeLine.append(element('span', 'api-label', 'Required scope'), element('code', 'api-scope', Array.isArray(scopes) ? scopes.join(', ') : scopes));
      body.append(scopeLine);
    }
    const parameters = parametersFor(path, operation, spec);
    if (parameters.length) {
      const parameterList = element('ul', 'api-parameter-list');
      parameters.forEach(parameter => {
        const schema = schemaInfo(parameter.schema, spec), item = element('li');
        item.append(element('code', '', `${parameter.name} (${parameter.in || 'parameter'}${parameter.required ? ', required' : ', optional'})`));
        item.append(element('p', '', [parameter.description, describeSchema(parameter.schema, spec), schemaNotes(schema, spec)].filter(Boolean).join(' · ')));
        const example = parameterExample(parameter, spec);
        item.append(element('p', 'api-parameter-example', `Example: ${valueText(example)}`));
        parameterList.append(item);
      });
      addSection(body, 'Parameters', parameterList);
    }
    const request = resolveRef(operation.requestBody, spec);
    if (request.content) {
      const requestContent = element('div', 'api-request-content');
      if (request.description) requestContent.append(element('p', '', request.description));
      requestContent.append(element('p', '', request.required ? 'Body required.' : 'Body optional.'));
      renderContent(requestContent, request.content, spec, 'Request');
      addSection(body, 'Request body', requestContent);
    }
    const curl = element('div');
    if (parameters.some(parameter => parameter.name === 'Idempotency-Key')) curl.append(element('p', 'api-example-description', 'Use a new Idempotency-Key for each operation. Reuse it when retrying the same request.'));
    let curls = 0;
    Object.entries(request.content || {}).forEach(([mediaType, definition]) => examplesFor(definition, spec).forEach(example => {
      if (!Object.hasOwn(example, 'value')) return;
      curl.append(codeExample(`curl · ${example.summary || example.name}`, curlExample(path, method, operation, spec, example.value, mediaType))); curls += 1;
    }));
    if (!curls) curl.append(codeExample('curl', curlExample(path, method, operation, spec)));
    addSection(body, 'Request examples', curl);
    if (operation.responses) {
      const responses = element('div', 'api-response-list');
      Object.entries(operation.responses).forEach(([status, raw]) => {
        const response = resolveRef(raw, spec), item = element('details', 'api-response');
        const heading = element('summary', 'api-response-summary');
        heading.append(element('code', 'api-status', status), document.createTextNode(` ${response.description || ''}`));
        item.append(heading);
        const responseBody = element('div', 'api-response-body');
        if (response.headers) {
          const headers = element('ul', 'api-parameter-list');
          Object.entries(response.headers).forEach(([name, rawHeader]) => {
            const header = resolveRef(rawHeader, spec), row = element('li');
            row.append(element('code', '', name), document.createTextNode(` — ${[header.description, describeSchema(header.schema, spec), schemaNotes(schemaInfo(header.schema, spec), spec)].filter(Boolean).join(' · ')}`));
            headers.append(row);
          });
          addSection(responseBody, 'Response headers', headers);
        }
        renderContent(responseBody, response.content, spec, `${status} response`);
        if (!response.content) responseBody.append(element('p', '', 'No response body.'));
        item.append(responseBody); responses.append(item);
      });
      addSection(body, 'Responses', responses);
    }
    details.append(body);
    details.dataset.search = [method, path, operation.summary, operation.description, scopes, ...parameters.map(parameter => parameter.name)].filter(Boolean).join(' ').toLocaleLowerCase();
    return details;
  };
  const renderOverview = spec => {
    if (!overview) return;
    const content = [];
    Object.values(spec.components?.securitySchemes || {}).forEach(scheme => {
      const prefix = scheme.type === 'http' && scheme.scheme?.toLowerCase() === 'bearer' ? 'Authorization: Bearer YOUR_KEEP_API_KEY' : `${scheme.name || scheme.scheme || scheme.type} (${scheme.in || 'authorization'})`;
      content.push(element('p', 'api-auth-header', prefix));
    });
    content.push(element('p', 'api-quick-start-note', 'Replace YOUR_KEEP_API_KEY with your key.'));
    const scopes = new Set();
    Object.values(spec.paths).forEach(path => Object.values(path).forEach(operation => {
      const required = operation?.['x-required-scope'];
      (Array.isArray(required) ? required : required ? [required] : []).forEach(scope => scopes.add(scope));
    }));
    const scopeList = element('ul', 'api-scope-list');
    [...scopes].sort().forEach(scope => {
      const row = element('li'); row.append(element('code', '', scope));
      if (spec['x-scope-descriptions']?.[scope]) row.append(document.createTextNode(` — ${spec['x-scope-descriptions'][scope]}`));
      scopeList.append(row);
    });
    if (scopes.size) content.push(element('h3', '', 'Available scopes'), scopeList);
    overview.replaceChildren(...content); overview.hidden = false;
  };
  const updateSearch = () => {
    const query = (search?.value || '').trim().toLocaleLowerCase();
    let visible = 0;
    const operations = [...list.querySelectorAll('.api-operation')];
    operations.forEach(operation => {
      operation.hidden = Boolean(query && !operation.dataset.search.includes(query));
      if (!operation.hidden) visible += 1;
    });
    if (clear) clear.hidden = !(search?.value || '');
    if (empty) empty.hidden = !query || visible > 0;
    if (searchStatus) searchStatus.textContent = `${visible} ${visible === 1 ? 'endpoint' : 'endpoints'}${query ? ' found' : ''}`;
  };
  search?.addEventListener('input', updateSearch);
  clear?.addEventListener('click', () => { search.value = ''; updateSearch(); search.focus({preventScroll: true}); });
  window.addEventListener('pageshow', updateSearch);
  const load = async () => {
    if (retry) retry.hidden = true;
    loadStatus.textContent = 'Loading endpoint definitions…';
    loadStatus.hidden = false;
    loadStatus.classList.remove('api-load-error');
    try {
      const response = await fetch(list.dataset.specUrl, {headers: {Accept: 'application/json'}, credentials: 'same-origin'});
      if (!response.ok) throw new Error('Specification unavailable');
      const spec = await response.json();
      if (!spec || spec.openapi !== '3.1.0' || !spec.paths || typeof spec.paths !== 'object') throw new Error('Invalid specification');
      const methods = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'];
      const operations = [];
      Object.entries(spec.paths).forEach(([path, pathItem]) => methods.forEach(method => {
        const operation = pathItem?.[method];
        if (operation && typeof operation === 'object') operations.push(renderOperation(path, method, operation, spec));
      }));
      if (!operations.length) throw new Error('No endpoint definitions');
      list.replaceChildren(...operations);
      renderOverview(spec); loadStatus.hidden = true; updateSearch();
    } catch (_) {
      loadStatus.textContent = 'Endpoint details could not be loaded. Try again or download the OpenAPI specification to review the contract.';
      loadStatus.classList.add('api-load-error');
      if (retry) retry.hidden = false;
    }
  };
  retry?.addEventListener('click', load);
  load();
})();
