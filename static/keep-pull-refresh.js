/* Page refresh gestures must never consume modal scrolling. */
(() => {
  const pullRefresh = document.getElementById("pull-refresh");
  const pullRefreshText = document.getElementById("pull-refresh-text");

  if (!pullRefresh || !pullRefreshText) return;
  const modalOpen = () => !!document.querySelector('dialog[open]');
  const reset = () => {
      pulling = false;
      pullDistance = 0;
      pullRefresh.classList.remove("visible", "ready");
      pullRefreshText.textContent = "Pull to refresh";
  };
  let pullStartY = 0;
  let pulling = false;
  let pullDistance = 0;
  const refreshThreshold = 85;

  document.addEventListener("touchstart", (event) => {
      reset();
      if (modalOpen() || window.scrollY !== 0 || event.touches.length !== 1) {
          return;
      }

      pullStartY = event.touches[0].clientY;
      pulling = true;
      pullDistance = 0;
  }, { passive: true });

  document.addEventListener("touchmove", (event) => {
      if (modalOpen() || event.touches.length !== 1) { reset(); return; }
      if (!pulling) {
          return;
      }

      pullDistance = event.touches[0].clientY - pullStartY;

      if (pullDistance <= 0) {
          pullRefresh.classList.remove("visible", "ready");
          return;
      }

      pullRefresh.classList.add("visible");

      if (pullDistance >= refreshThreshold) {
          pullRefresh.classList.add("ready");
          pullRefreshText.textContent = "Release to refresh";
      } else {
          pullRefresh.classList.remove("ready");
          pullRefreshText.textContent = "Pull to refresh";
      }
  }, { passive: true });

  document.addEventListener("touchend", () => {
      if (modalOpen()) { reset(); return; }
      if (!pulling) {
          return;
      }

      pulling = false;

      if (pullDistance >= refreshThreshold) {
          pullRefreshText.textContent = "Refreshing...";
          window.location.reload();
          return;
      }

      pullRefresh.classList.remove("visible", "ready");
      pullRefreshText.textContent = "Pull to refresh";
      pullDistance = 0;
  });

  document.addEventListener("touchcancel", reset, { passive: true });
})();
