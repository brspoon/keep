/* Build the reference from the checked-in OpenAPI contract. This page never sends API requests. */
(() => {
  const list = document.getElementById('api-operation-list');
  const loadStatus = document.getElementById('api-load-status');
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
  const describeSchema = schema => {
    if (!schema || typeof schema !== 'object') return 'value';
    if (schema.$ref) return schema.$ref.split('/').pop();
    const type = Array.isArray(schema.type) ? schema.type.join(' or ') : schema.type;
    if (schema.enum) return `${type || 'value'}: ${schema.enum.join(', ')}`;
    if (schema.format) return `${type || 'value'} (${schema.format})`;
    return type || 'value';
  };
  const resolveRef = (value, spec) => {
    if (!value?.$ref || !value.$ref.startsWith('#/')) return value;
    return value.$ref.slice(2).split('/').reduce((current, key) => current?.[key], spec) || value;
  };
  const addSection = (container, title, content) => {
    const section = element('section', 'api-detail-section');
    section.append(element('h4', '', title), content);
    container.append(section);
  };
  const renderOperation = (path, method, operation, spec) => {
    const details = element('details', 'api-operation');
    details.setAttribute('role', 'listitem');
    const summary = element('summary', 'api-operation-summary');
    const methodBadge = element('span', `api-method api-method-${method}`, method.toUpperCase());
    const pathText = element('code', 'api-path', spec.servers?.[0]?.url + path);
    const summaryText = element('span', 'api-operation-title', operation.summary || operation.operationId || path);
    summary.append(methodBadge, pathText, summaryText);
    details.append(summary);
    const body = element('div', 'api-operation-body');
    if (operation.description) body.append(element('p', 'api-operation-description', operation.description));
    const scopes = operation['x-required-scope'];
    if (typeof scopes === 'string') {
      const scopeLine = element('p', 'api-scope-line');
      scopeLine.append(element('span', 'api-label', 'Required scope'), element('code', 'api-scope', scopes));
      body.append(scopeLine);
    }

    const parameters = [...(operation.parameters || []), ...(spec.paths[path].parameters || [])]
      .map(parameter => resolveRef(parameter, spec));
    if (parameters.length) {
      const list = element('ul', 'api-parameter-list');
      parameters.forEach(parameter => {
        if (parameter.$ref) return;
        const item = element('li');
        const location = parameter.in === 'header' ? 'header' : parameter.in === 'path' ? 'path' : 'query';
        item.append(element('code', '', `${parameter.name} (${location}${parameter.required ? ', required' : ''})`));
        item.append(document.createTextNode(` — ${parameter.description || describeSchema(parameter.schema)}`));
        list.append(item);
      });
      if (list.childElementCount) addSection(body, 'Parameters', list);
    }

    const request = operation.requestBody;
    if (request?.content) {
      const requestContent = element('div', 'api-request-content');
      Object.entries(request.content).forEach(([mediaType, definition]) => {
        requestContent.append(element('p', '', `${mediaType}${request.required ? ' · required' : ''}`));
        const examples = definition.examples || {};
        const example = Object.values(examples)[0]?.value;
        if (example !== undefined) {
          const pre = element('pre', 'api-code-example');
          pre.append(element('code', '', JSON.stringify(example, null, 2)));
          requestContent.append(pre);
        } else if (definition.schema) {
          requestContent.append(element('p', 'api-schema-name', `Schema: ${describeSchema(definition.schema)}`));
        }
      });
      addSection(body, 'Request body', requestContent);
    }

    if (operation.responses) {
      const responses = element('ul', 'api-response-list');
      Object.entries(operation.responses).forEach(([status, response]) => {
        response = resolveRef(response, spec);
        const item = element('li');
        item.append(element('code', 'api-status', status));
        item.append(document.createTextNode(` ${response.description || ''}`));
        const jsonBody = response.content?.['application/json'];
        if (jsonBody?.schema) item.append(document.createTextNode(` · ${describeSchema(jsonBody.schema)}`));
        responses.append(item);
      });
      addSection(body, 'Responses', responses);
    }
    details.append(body);
    details.dataset.search = [method, path, operation.summary, operation.description, scopes].filter(Boolean).join(' ').toLocaleLowerCase();
    return details;
  };

  const updateSearch = () => {
    const query = (search?.value || '').trim().toLocaleLowerCase();
    let visible = 0;
    const operations = [...list.querySelectorAll('.api-operation')];
    operations.forEach(operation => {
      operation.hidden = Boolean(query && !operation.dataset.search.includes(query));
      if (!operation.hidden) visible += 1;
    });
    if (clear) clear.hidden = !query;
    if (empty) empty.hidden = !query || visible > 0;
    if (searchStatus) searchStatus.textContent = query ? `${visible} ${visible === 1 ? 'endpoint' : 'endpoints'} found` : `${visible} endpoints`;
  };
  search?.addEventListener('input', updateSearch);
  clear?.addEventListener('click', () => {
    search.value = '';
    updateSearch();
    search.focus();
  });

  const load = async () => {
    try {
      const response = await fetch(list.dataset.specUrl, {headers: {Accept: 'application/json'}, credentials: 'same-origin'});
      if (!response.ok) throw new Error('Specification unavailable');
      const spec = await response.json();
      if (!spec || spec.openapi !== '3.1.0' || !spec.paths || typeof spec.paths !== 'object') throw new Error('Invalid specification');
      const methodOrder = ['get', 'post', 'patch', 'delete'];
      const operations = [];
      Object.entries(spec.paths).forEach(([path, pathItem]) => {
        methodOrder.forEach(method => {
          const operation = pathItem?.[method];
          if (operation && typeof operation === 'object') operations.push(renderOperation(path, method, operation, spec));
        });
      });
      if (!operations.length) throw new Error('No endpoint definitions');
      list.replaceChildren(...operations);
      loadStatus.hidden = true;
      updateSearch();
    } catch (_) {
      loadStatus.textContent = 'Endpoint details could not be loaded. Open the OpenAPI specification directly to review the contract.';
      loadStatus.classList.add('api-load-error');
    }
  };
  load();
})();
