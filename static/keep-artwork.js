/* Request visible posters first, then one viewport ahead. Native lazy loading
   remains the fallback; no inventory-wide preload or background downloads. */
(() => {
  const posters = [...document.querySelectorAll('.library-management-ui img.poster')];
  if (!('IntersectionObserver' in window)) return;
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      const image = entry.target;
      const rect = image.getBoundingClientRect();
      image.fetchPriority = rect.top < window.innerHeight && rect.bottom > 0 ? 'high' : 'low';
      image.loading = 'eager';
      observer.unobserve(image);
    }
  }, {rootMargin: `${window.innerHeight}px 0px`});
  for (const image of posters) observer.observe(image);
})();
