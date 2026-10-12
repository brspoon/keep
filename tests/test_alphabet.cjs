const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('static/keep-alphabet.js', 'utf8');

function fixture(groups, {reduced = true, observerAvailable = true} = {}) {
  let document;
  class Element {
    constructor(tag = 'div', className = '', text = '') {
      this.tagName = tag.toUpperCase(); this.className = className; this._text = text;
      this.children = []; this.dataset = {}; this.attrs = {}; this.listeners = {}; this.hidden = false; this.value = ''; this.replacements = 0;
      this.classList = {contains: name => this.className.split(' ').includes(name)};
      this.rect = {top:800, height:80};
    }
    set innerHTML(_) { throw new Error('Title and collection names must remain text'); }
    get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
    set textContent(value) { this._text = String(value); this.children = []; }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; this.replacements++; }
    setAttribute(name, value) { this.attrs[name] = String(value); }
    querySelectorAll(selector) {
      const matches = node => selector.startsWith('.') ? node.classList.contains(selector.slice(1)) : selector === '[data-alphabet-nav]' ? Object.hasOwn(node.attrs, 'data-alphabet-nav') : node.tagName === selector.toUpperCase();
      return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
    fire(type, extra = {}) {
      const event = {target:this, preventDefault() {this.prevented = true;}, ...extra};
      (this.listeners[type] || []).forEach(handler => handler(event)); return event;
    }
    focus(options) { document.activeElement = this; this.focusOptions = options; this.focusCount = (this.focusCount || 0) + 1; }
    scrollIntoView(options) { this.scrollOptions = options; }
    getBoundingClientRect() { return this.rect; }
  }
  const view = new Element('div', 'media-view');
  const sections = groups.map(group => {
    const section = new Element('section'), header = new Element('div', 'section-header'), title = new Element('h2', '', group.name);
    const nav = new Element('nav', 'alphabet-nav'), strip = new Element('div', 'alphabet-letters'), grid = new Element('div', 'grid');
    nav.setAttribute('data-alphabet-nav', ''); nav.append(strip); header.append(title, nav);
    section.cards = group.titles.map(value => {
      const card = new Element('article', 'card'); card.dataset.title = typeof value === 'string' ? value : value.title; card.hidden = Boolean(value.hidden);
      card.append(new Element('div', 'title', card.dataset.title)); return card;
    });
    grid.append(...section.cards); section.append(header, grid); section.hidden = Boolean(group.hidden); return section;
  });
  view.append(...sections);
  const search = new Element('input'), clear = new Element('button'), scope = new Element('button'), root = new Element('html');
  document = {documentElement: root, activeElement: null,
    querySelectorAll: selector => selector === '.media-view section[data-alphabet-section]' ? sections : selector === '.media-view' ? [view] : selector === '[data-keep-scope]' ? [scope] : [],
    getElementById: id => id === 'media-search' ? search : id === 'search-clear' ? clear : null,
    createElement: tag => new Element(tag)};
  const frames = [], observers = [], scrolls = [];
  class MutationObserver {
    constructor(callback) { this.callback = callback; observers.push(this); }
    observe(target, options) { this.target = target; this.options = options; }
  }
  const window = new Element('window'); window.scrollY = 500;
  window.matchMedia = () => ({matches: reduced}); window.scrollTo = options => scrolls.push(options);
  if (observerAvailable) window.MutationObserver = MutationObserver;
  let offset = '120px';
  vm.runInNewContext(source, {document, window, MutationObserver, requestAnimationFrame: callback => frames.push(callback),
    getComputedStyle: () => ({getPropertyValue: () => offset}), parseFloat});
  const buttons = section => section.querySelectorAll('.alphabet-letter');
  return {document, window, sections, search, clear, scope, scrolls, frames, observers, buttons,
    visible: section => buttons(section).filter(button => !button.hidden).map(button => button.textContent),
    button: (section, letter) => buttons(section).find(button => button.dataset.letter === letter),
    picker: section => section.querySelector('select'),
    setOffset: value => {offset = value;}, flush: () => { while (frames.length) frames.shift()(); }};
}

test('each section indexes its own first visible cards without reordering media', () => {
  const f = fixture([{name:'Movies', titles:['Alpha', 'Another', 'Zulu']}, {name:'Shows', titles:['Beta', 'Zulu']}]);
  const [movies, shows] = f.sections;
  assert.deepEqual(f.visible(movies), ['A','Z']); assert.deepEqual(f.visible(shows), ['B','Z']);
  const before = [...movies.cards];
  f.button(movies, 'A').fire('click');
  assert.equal(f.document.activeElement, movies.cards[0]); assert.equal(movies.cards[0].tabIndex, -1);
  assert.equal(movies.cards[0].focusOptions.preventScroll, true);
  assert.equal(f.scrolls[0].top, 1092); assert.equal(f.scrolls[0].behavior, 'auto');
  f.button(shows, 'Z').fire('click'); assert.equal(f.document.activeElement, shows.cards[1]);
  assert.deepEqual(movies.cards, before);
  assert.match(f.button(movies, 'A').attrs['aria-label'], /in Movies/);
  assert.match(f.button(shows, 'Z').attrs['aria-label'], /in Shows/);
});

test('filter and My Keeps changes remove unavailable letters and retarget the first visible match', () => {
  const f = fixture([{name:'Kept', titles:['Alpha','Another','Beta']}]);
  const section = f.sections[0];
  section.cards[0].hidden = true; section.cards[2].hidden = true;
  f.search.fire('input'); assert.deepEqual(f.visible(section), ['A']);
  f.button(section, 'A').fire('click'); assert.equal(f.document.activeElement, section.cards[1]);
  section.hidden = true; f.scope.fire('click');
  assert.equal(section.querySelector('[data-alphabet-nav]').hidden, true);
  assert.deepEqual(f.visible(section), []);
  section.hidden = false; section.cards.forEach(card => {card.hidden = false;}); f.clear.fire('click');
  assert.deepEqual(f.visible(section), ['A','B']);
});

test('numbers, punctuation, accented and non-Latin initials use # without changing display order', () => {
  const f = fixture([{name:'Library', titles:['2001', '"Alpha"', 'a movie', ' The movie', 'Éclair', 'Σειρά', '中文']}]);
  const section = f.sections[0]; assert.deepEqual(f.visible(section), ['#','A','T']);
  f.button(section, '#').fire('click'); assert.equal(f.document.activeElement, section.cards[0]);
  section.cards[0].hidden = true; section.cards[1].hidden = true; f.search.fire('input');
  f.button(section, '#').fire('click'); assert.equal(f.document.activeElement, section.cards[4]);
  assert.match(f.button(section, '#').attrs['aria-label'], /Numbers and other titles/);
});

test('mobile picker has available letters, resets for repeat selection, and focuses only after select commit', () => {
  const f = fixture([{name:'Movies', titles:['Alpha','Beta']}]);
  const section = f.sections[0], picker = f.picker(section);
  assert.equal(picker.children[0].textContent, 'Jump to letter');
  assert.deepEqual(picker.children.map(option => option.value), ['', 'A', 'B']);
  assert.equal(picker.attrs['aria-label'], 'Jump to letter in Movies');
  picker.value = 'B'; picker.fire('change');
  assert.equal(picker.value, ''); assert.equal(f.scrolls.length, 0);
  // The existing select component restores its trigger immediately after committing.
  f.document.activeElement = 'shared select trigger'; f.flush();
  assert.equal(f.document.activeElement, section.cards[1]);
  picker.value = 'B'; picker.fire('change'); f.flush();
  assert.equal(section.cards[1].focusCount, 2);
  const replacementCount = picker.replacements; f.window.KeepAlphabet.refresh();
  assert.equal(picker.replacements, replacementCount, 'unchanged options must not reset an open picker');
});

test('stale letter activation and queued mobile jumps never focus hidden or removed titles', () => {
  const f = fixture([{name:'Movies', titles:['Alpha','Beta']}]);
  const section = f.sections[0], picker = f.picker(section);
  picker.value = 'B'; picker.fire('change'); section.cards[1].hidden = true; f.flush();
  assert.equal(f.scrolls.length, 0); assert.equal(f.document.activeElement, null);
  f.button(section, 'B').fire('click'); assert.equal(f.scrolls.length, 0);
  section.querySelector('.grid').children = []; section.cards = [];
  f.window.fire('pageshow'); assert.equal(section.querySelector('[data-alphabet-nav]').hidden, true);
  assert.deepEqual(picker.children.map(option => option.value), ['']);
});

test('arrow and edge keys move through available letters without running media actions', () => {
  const f = fixture([{name:'Movies', titles:['Alpha','Beta','Zulu']}]);
  const section = f.sections[0];
  assert.equal(f.button(section,'A').fire('keydown', {key:'ArrowRight'}).prevented, true);
  assert.equal(f.document.activeElement, f.button(section,'B'));
  f.button(section,'B').fire('keydown', {key:'End'}); assert.equal(f.document.activeElement, f.button(section,'Z'));
  f.button(section,'Z').fire('keydown', {key:'ArrowRight'}); assert.equal(f.document.activeElement, f.button(section,'A'));
  f.button(section,'A').fire('keydown', {key:'Home'}); assert.equal(f.document.activeElement, f.button(section,'A'));
  assert.equal(f.scrolls.length, 0);
});

test('jump offsets use current sticky sizes and smooth movement respects reduced motion', () => {
  const f = fixture([{name:'Movies', titles:['Alpha']}], {reduced:false});
  const section = f.sections[0]; f.setOffset('200px'); section.querySelector('.section-header').rect.height = 100;
  f.button(section,'A').fire('click'); assert.equal(f.scrolls[0].top, 992); assert.equal(f.scrolls[0].behavior, 'smooth');
  section.cards[0].rect.top = -1000; f.button(section,'A').fire('click'); assert.equal(f.scrolls[1].top, 0);
});

test('card removal and hidden mutations refresh once, while generated controls do not trigger observer loops', () => {
  const f = fixture([{name:'Movies', titles:['Alpha','Beta']}]);
  const section = f.sections[0], observer = f.observers[0];
  observer.callback([{type:'childList', target:section.querySelector('[data-alphabet-nav]'), addedNodes:[f.picker(section)], removedNodes:[]}]);
  assert.equal(f.frames.length, 0);
  section.querySelector('.grid').children.shift();
  observer.callback([{type:'childList', target:section.querySelector('.grid'), addedNodes:[], removedNodes:[section.cards[0]]}]);
  observer.callback([{type:'attributes', target:section.cards[1]}]);
  assert.equal(f.frames.length, 1); f.flush(); assert.deepEqual(f.visible(section), ['B']);
});

test('names remain text and navigation still refreshes without MutationObserver', () => {
  const f = fixture([{name:'<img onerror=alert(1)>', titles:['Alpha']}], {observerAvailable:false});
  const section = f.sections[0]; assert.match(f.button(section,'A').attrs['aria-label'], /<img onerror=/);
  section.cards[0].hidden = true; f.window.fire('pageshow'); assert.deepEqual(f.visible(section), []);
});
