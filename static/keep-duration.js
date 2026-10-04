(() => {
  const keepDialog = document.getElementById('keep-duration-dialog');
  const manageDialog = document.getElementById('manage-keep-dialog');

  function trapFocus(dialog, controls, isSubmitting) {
    dialog.addEventListener('keydown', event => {
      if (event.key !== 'Tab' || isSubmitting()) return;
      const available = controls().filter(control => !control.disabled);
      const first = available[0];
      const last = available[available.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault(); first.focus();
      }
    });
  }

  function unlockPage() {
    document.documentElement.classList.remove('keep-duration-open');
  }

  async function submitNewKeep(opener, duration, title) {
    const response = await fetch('/api/keep', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': (keepDialog || opener).dataset.csrf
      },
      body: JSON.stringify({
        mediaId: opener.dataset.mediaId,
        collectionId: Number(opener.dataset.collectionId),
        duration
      })
    });
    if (!response.ok) throw new Error('Keep request failed');

    const card = opener.closest('.card');
    const section = opener.closest('section');
    refreshCounts(true);
    showToast(duration === 'temporary' ? `${title} is protected for 30 days` : `${title} is kept indefinitely`);
    await (window.KeepUI?.finishMediaAction || ((item, button, updateLayout) => {
      item.remove(); updateLayout();
    }))(card, opener, () => {
      const count = section.querySelector('.count');
      const remaining = section.querySelectorAll('.card').length;
      count.textContent = remaining;
      applyMediaSearch();
    }, 'Kept ✓', false);
  }

  document.querySelectorAll('.new-keep-button[data-direct-temporary="true"]').forEach(button => {
    let armed = false;
    let timer = null;
    const reset = () => {
      clearTimeout(timer);
      armed = false;
      button.disabled = false;
      button.dataset.confirming = 'false';
      button.textContent = 'KEEP';
    };
    button.dataset.csrf = document.body.dataset.csrf || '';
    button.addEventListener('click', async () => {
      if (!armed) {
        armed = true;
        button.dataset.confirming = 'true';
        button.textContent = 'KEEP FOR 30 DAYS?';
        timer = setTimeout(reset, 4000);
        return;
      }
      clearTimeout(timer);
      button.disabled = true;
      button.textContent = 'KEEPING…';
      const title = button.closest('.card').querySelector('.title').textContent.trim();
      try {
        await submitNewKeep(button, 'temporary', title);
      } catch (requestError) {
        reset();
        window.showToast?.('Couldn’t protect this title. Please try again.');
      }
    });
    button.addEventListener('blur', () => { if (armed && !button.disabled) reset(); });
  });

  if (keepDialog) {
    const heading = keepDialog.querySelector('h2');
    const close = keepDialog.querySelector('.welcome-close');
    const cancel = keepDialog.querySelector('.keep-duration-cancel');
    const choices = [...keepDialog.querySelectorAll('[data-duration]')];
    const error = keepDialog.querySelector('.welcome-error');
    let opener = null;
    let title = '';
    let submitting = false;

    function resetDialog() {
      submitting = false;
      error.hidden = true;
      choices.forEach(choice => { choice.disabled = false; });
      cancel.disabled = false;
      close.disabled = false;
    }

    [...document.querySelectorAll('.new-keep-button')]
      .filter(button => button.dataset.directTemporary !== 'true')
      .forEach(button => {
      button.addEventListener('click', () => {
        opener = button;
        title = button.closest('.card').querySelector('.title').textContent.trim();
        heading.textContent = `Keep ${title}?`;
        resetDialog();
        keepDialog.showModal();
        document.documentElement.classList.add('keep-duration-open');
        choices[0].focus({ preventScroll: true });
      });
      });

    choices.forEach(choice => {
      choice.addEventListener('click', async () => {
        if (submitting || !opener) return;
        submitting = true;
        error.hidden = true;
        choices.forEach(button => { button.disabled = true; });
        cancel.disabled = true;
        close.disabled = true;
        const duration = choice.dataset.duration;
        try {
          const actionButton = opener;
          await submitNewKeep(actionButton, duration, title);
          opener = null;
          keepDialog.close();
        } catch (requestError) {
          resetDialog();
          error.hidden = false;
          choices[0].focus({ preventScroll: true });
        }
      });
    });

    function dismiss() {
      if (!submitting) keepDialog.close();
    }
    close.addEventListener('click', dismiss);
    cancel.addEventListener('click', dismiss);
    keepDialog.addEventListener('cancel', event => {
      if (submitting) event.preventDefault();
    });
    trapFocus(keepDialog, () => [close, ...choices, cancel], () => submitting);
    keepDialog.addEventListener('close', () => {
      unlockPage();
      if (opener?.isConnected) opener.focus({ preventScroll: true });
    });
  }

  if (manageDialog) {
    const heading = manageDialog.querySelector('h2');
    const description = manageDialog.querySelector('.welcome-intro');
    const close = manageDialog.querySelector('.welcome-close');
    const cancel = manageDialog.querySelector('.keep-duration-cancel');
    const choices = [...manageDialog.querySelectorAll('[data-duration]')];
    const temporary = choices.find(choice => choice.dataset.duration === 'temporary');
    const indefinite = choices.find(choice => choice.dataset.duration === 'indefinite');
    const temporaryTitle = temporary.querySelector('[data-option-title]');
    const temporaryDetail = temporary.querySelector('[data-option-detail]');
    const indefiniteDetail = indefinite?.querySelector('[data-option-detail]');
    const error = manageDialog.querySelector('.welcome-error');
    let opener = null;
    let submitting = false;

    function configureDialog() {
      const isTemporary = opener.dataset.isTemporary === 'true';
      const canExtend = opener.dataset.canExtend !== 'false';
      const days = Number(opener.dataset.daysLeft);
      heading.textContent = `Manage ${opener.closest('.card').querySelector('.title').textContent.trim()}`;
      description.textContent = isTemporary
        ? `Currently protected for ${days} ${days === 1 ? 'day' : 'days'}, through ${opener.dataset.expiryLabel}. Choose a change below; selecting it applies immediately.`
        : 'Currently protected indefinitely. Choose a change below; selecting it applies immediately.';
      temporaryTitle.textContent = isTemporary ? 'Extend by 30 days' : 'Switch to a 30-day keep';
      temporaryDetail.textContent = isTemporary && !canExtend
        ? `Available ${opener.dataset.extensionAvailableLabel}`
        : `${isTemporary ? 'New expiration' : 'Expires'}: ${opener.dataset.nextTemporaryLabel}`;
      if (indefiniteDetail) indefiniteDetail.textContent = isTemporary
          ? 'Protected until someone removes the keep'
          : 'Current protection';
      choices.forEach(choice => { choice.disabled = false; });
      temporary.disabled = isTemporary && !canExtend;
      if (indefinite) {
        indefinite.disabled = !isTemporary;
        indefinite.classList.toggle('is-current', !isTemporary);
        if (isTemporary) indefinite.removeAttribute('aria-current');
        else indefinite.setAttribute('aria-current', 'true');
      }
      error.hidden = true;
      cancel.disabled = false;
      close.disabled = false;
      submitting = false;
    }

    document.querySelectorAll('.keep-manage-button').forEach(button => {
      button.addEventListener('click', () => {
        opener = button;
        configureDialog();
        manageDialog.showModal();
        document.documentElement.classList.add('keep-duration-open');
        (choices.find(choice => !choice.disabled) || cancel).focus({ preventScroll: true });
      });
    });

    choices.forEach(choice => {
      choice.addEventListener('click', async () => {
        if (submitting || !opener || choice.disabled) return;
        submitting = true;
        error.hidden = true;
        choices.forEach(button => { button.disabled = true; });
        cancel.disabled = true;
        close.disabled = true;
        const duration = choice.dataset.duration;
        const actionButton = opener;
        const original = actionButton.textContent;
        actionButton.disabled = true;
        actionButton.textContent = 'UPDATING…';
        try {
          const response = await fetch('/api/update-keep', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': manageDialog.dataset.csrf
            },
            body: JSON.stringify({
              mediaId: actionButton.dataset.mediaId,
              collectionId: Number(actionButton.dataset.collectionId),
              duration
            })
          });
          if (!response.ok) throw new Error('Keep update failed');
          actionButton.textContent = 'UPDATED ✓';
          manageDialog.close();
          const message = duration === 'temporary'
            ? (actionButton.dataset.isTemporary === 'true' ? 'Keep extended by 30 days' : 'Title protected for 30 days')
            : 'Title kept indefinitely';
          showToast(message);
          window.KeepToastAfterReload?.(message);
          setTimeout(() => window.location.reload(), 650);
        } catch (requestError) {
          actionButton.disabled = false;
          actionButton.textContent = original;
          configureDialog();
          error.hidden = false;
          (choices.find(button => !button.disabled) || cancel).focus({ preventScroll: true });
        }
      });
    });

    function dismiss() {
      if (!submitting) manageDialog.close();
    }
    close.addEventListener('click', dismiss);
    cancel.addEventListener('click', dismiss);
    manageDialog.addEventListener('cancel', event => {
      if (submitting) event.preventDefault();
    });
    trapFocus(manageDialog, () => [close, ...choices, cancel], () => submitting);
    manageDialog.addEventListener('close', () => {
      unlockPage();
      if (opener?.isConnected) opener.focus({ preventScroll: true });
    });
  }
})();
