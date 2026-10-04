const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

// Exercise the inline browse controls that the Flask template serves.
const source = fs.readFileSync('app.py', 'utf8');
const controls = source.slice(source.indexOf('        const mediaSearch ='),
  source.indexOf('        async function refreshCounts('));

function fixture() {
  const element = () => ({hidden:false, textContent:'', value:'', dataset:{}, listeners:{},
    addEventListener(name, handler) { this.listeners[name] = handler; },
    setAttribute(name, value) { this[name] = value; }, focus() {}});
  const search = element(), clear = element(), status = element(), searchEmpty = element();
  const browseEmpty = element(), emptyTitle = element(), emptyDescription = element(), nav = element();
  browseEmpty.dataset = {title:'Nothing kept just yet', description:'Give a favorite a Keep.'};
  browseEmpty.querySelector = selector => selector === '[data-browse-empty-title]' ? emptyTitle : emptyDescription;
  const scopeAll = element(), scopeMine = element();
  scopeAll.dataset.keepScope = 'all'; scopeMine.dataset.keepScope = 'mine';
  const card = (title, own) => ({hidden:false, dataset:{keptByViewer:String(own)},
    querySelector:selector => ({textContent:selector === '.title' ? title : '2026'})});
  const movies = {id:'collection-1', hidden:false, cards:[card('Alpha', true), card('Beta', false)], count:element()};
  const shows = {id:'collection-3', hidden:false, cards:[card('Zulu', false)], count:element()};
  const sections = [movies, shows];
  for (const section of sections) {
    section.querySelectorAll = () => section.cards;
    section.querySelector = () => section.count;
  }
  const links = sections.map(section => ({hidden:false, getAttribute:() => `#${section.id}`}));
  const document = {
    getElementById:id => ({'media-search':search, 'search-clear':clear, 'search-status':status,
      'search-empty':searchEmpty, 'browse-empty':browseEmpty}[id]),
    querySelector:() => nav,
    querySelectorAll:selector => selector === '.media-view section' ? sections
      : selector === '.section-nav a' ? links : [scopeAll, scopeMine]
  };
  const context = {document, window:{addEventListener() {}}};
  vm.runInNewContext(controls, context);
  return {search, clear, status, searchEmpty, browseEmpty, emptyTitle, emptyDescription, nav,
    scopeAll, scopeMine, movies, shows, links, apply:context.applyMediaSearch};
}

test('My Keeps hides sections and jump links with no personal keeps, then restores All Keeps', () => {
  const f = fixture(); f.scopeMine.listeners.click();
  assert.equal(f.movies.hidden, false); assert.equal(f.movies.count.textContent, 1);
  assert.equal(f.movies.cards[1].hidden, true);
  assert.equal(f.shows.hidden, true); assert.equal(f.links[1].hidden, true);
  assert.equal(f.scopeMine['aria-pressed'], 'true');
  f.scopeAll.listeners.click();
  assert.equal(f.shows.hidden, false); assert.equal(f.links[1].hidden, false);
  assert.equal(f.movies.count.textContent, 2); assert.equal(f.browseEmpty.hidden, true);
});

test('empty My Keeps and searches show the appropriate page note and recover on clear', () => {
  const f = fixture(); f.movies.cards[0].dataset.keptByViewer = 'false'; f.scopeMine.listeners.click();
  assert.equal(f.movies.hidden, true); assert.equal(f.shows.hidden, true);
  assert.equal(f.nav.hidden, true); assert.equal(f.browseEmpty.hidden, false);
  assert.equal(f.emptyTitle.textContent, 'Your favorites are waiting');
  assert.match(f.emptyDescription.textContent, /haven’t kept any titles/);
  f.search.value = 'Alpha'; f.search.listeners.input();
  assert.equal(f.browseEmpty.hidden, true); assert.equal(f.searchEmpty.hidden, false);
  assert.equal(f.searchEmpty.textContent, 'No titles in My Keeps match your search.');
  f.scopeAll.listeners.click();
  assert.equal(f.movies.hidden, false); assert.equal(f.shows.hidden, true);
  assert.equal(f.links[0].hidden, false); assert.equal(f.links[1].hidden, true);
  f.clear.listeners.click();
  assert.equal(f.shows.hidden, false); assert.equal(f.nav.hidden, false);
  assert.equal(f.browseEmpty.hidden, true); assert.equal(f.searchEmpty.hidden, true);
});

test('removing the final title hides its section and button and shows one page note', () => {
  const f = fixture(); f.movies.cards = []; f.apply();
  assert.equal(f.movies.hidden, true); assert.equal(f.links[0].hidden, true);
  assert.equal(f.shows.hidden, false); assert.equal(f.browseEmpty.hidden, true);
  f.shows.cards = []; f.apply();
  assert.equal(f.shows.hidden, true); assert.equal(f.links[1].hidden, true);
  assert.equal(f.nav.hidden, true); assert.equal(f.browseEmpty.hidden, false);
  assert.equal(f.emptyTitle.textContent, 'Nothing kept just yet');
});
