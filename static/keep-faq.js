/* Render current Leaving rules as readable, expandable answers. */
(() => {
  const root = document.getElementById('faq-criteria');
  if (!root) return;
  const search = document.getElementById('faq-search');
  const clear = document.getElementById('faq-search-clear');
  const status = document.getElementById('faq-search-status');
  const empty = document.getElementById('faq-search-empty');
  const sections = search ? [...document.querySelectorAll('.faq-section')] : [];
  const topics = search ? [...document.querySelectorAll('[data-faq-topic]')] : [];
  const popular = document.querySelector('.faq-popular');
  const originalOpen = new Map();
  const openHashQuestion = () => {
    const id = decodeURIComponent(window.location.hash.slice(1));
    const question = id && document.getElementById(id);
    if (question?.classList?.contains('faq-question')) question.open = true;
  };
  const updateSearch = () => {
    if (!search) return;
    const query = search.value.trim().toLocaleLowerCase();
    let matches = 0;
    sections.forEach(section => {
      const heading = section.querySelector('.faq-section-head');
      const headingMatches = heading.textContent.toLocaleLowerCase().includes(query);
      const questions = [...section.querySelectorAll('.faq-question')];
      questions.forEach(question => {
        const questionMatches = headingMatches || question.textContent.toLocaleLowerCase().includes(query);
        question.hidden = Boolean(query && !questionMatches);
        if (!question.hidden) matches += 1;
        if (query && !question.hidden) {
          if (!originalOpen.has(question)) originalOpen.set(question, question.open);
          question.open = true;
        } else if (originalOpen.has(question)) {
          question.open = originalOpen.get(question);
          originalOpen.delete(question);
        }
      });
      section.hidden = Boolean(query && questions.every(question => question.hidden));
    });
    topics.forEach(topic => {
      topic.hidden = Boolean(query && document.getElementById(topic.dataset.faqTopic)?.hidden);
    });
    if (popular) popular.hidden = Boolean(query);
    for (const detail of root.querySelectorAll('details')) {
      if (query) {
        if (!originalOpen.has(detail)) originalOpen.set(detail, detail.open);
        detail.open = detail.textContent.toLocaleLowerCase().includes(query);
      } else if (originalOpen.has(detail)) {
        detail.open = originalOpen.get(detail);
        originalOpen.delete(detail);
      }
    }
    clear.hidden = !query;
    empty.hidden = !query || matches > 0;
    status.textContent = query ? `${matches} ${matches === 1 ? 'question' : 'questions'} found` : '';
  };
  search?.addEventListener('input', updateSearch);
  clear?.addEventListener('click', () => {
    search.value = '';
    updateSearch();
    search.focus();
  });
  popular?.querySelectorAll('a[href^="#faq-"]').forEach(link => {
    link.addEventListener('click', () => {
      const question = document.getElementById(link.hash.slice(1));
      if (question) question.open = true;
    });
  });
  window.addEventListener('hashchange', openHashQuestion);
  openHashQuestion();
  const load = async () => {
    try {
      const response = await fetch('/api/leaving-criteria', {credentials: 'same-origin'});
      if (!response.ok) throw new Error('Rules unavailable');
      const groups = await response.json();
      if (!Array.isArray(groups) || !groups.length) throw new Error('No rules');
      const sections = groups.map(group => {
        if (!group || typeof group.name !== 'string' || !['movie', 'tv'].includes(group.kind) || !Array.isArray(group.paths)) throw new Error('Invalid rules');
        const section = document.createElement('details');
        const heading = document.createElement('summary');
        heading.textContent = group.name;
        const intro = document.createElement('p');
        const title = group.kind === 'movie' ? 'movie' : 'show';
        const watched = group.kind === 'movie'
          ? `A movie is considered watched when someone watches at least ${group.watched_percent}% of it. `
          : `A show is considered watched when someone watches at least ${group.watched_percent}% of one of its episodes. `;
        intro.textContent = (group.watched_percent ? watched : '') +
          `A ${title} may appear in Leaving if any of these apply:`;
        const list = document.createElement('ul');
        group.paths.forEach(path => {
          if (typeof path !== 'string') throw new Error('Invalid rule');
          const item = document.createElement('li');
          item.textContent = path;
          list.append(item);
        });
        section.append(heading, intro, list);
        return section;
      });
      root.replaceChildren(...sections);
      root.removeAttribute('role');
      root.removeAttribute('aria-live');
    } catch (_) {
      root.textContent = 'Current Leaving rules could not be loaded. Please try refreshing this page.';
    }
    updateSearch();
  };
  load();
})();
