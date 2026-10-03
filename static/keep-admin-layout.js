/* Arrange admin tools without changing their server-side form contracts. */
(() => {
  if (!document.body.classList.contains('admin-ui')) return;
  const navigation = document.querySelector('.admin-nav');
  const currentTab = navigation?.querySelector('[aria-current="page"]');
  if (currentTab && navigation.scrollWidth > navigation.clientWidth) {
    navigation.scrollLeft = currentTab.offsetLeft - navigation.offsetLeft - (navigation.clientWidth - currentTab.offsetWidth) / 2;
  }
  const creation = document.querySelector('.creation-panel');
  const search = document.querySelector('.admin-list-search');
  if (creation && search) {
    const dialog = document.createElement('dialog'); dialog.className='admin-create-dialog'; dialog.setAttribute('aria-labelledby','create-title');
    const heading = document.createElement('h2'); heading.id='create-title'; heading.tabIndex=-1; heading.autofocus=true; heading.textContent=creation.querySelector('summary span').textContent;
    const open = document.querySelector('.admin-add-button');
    const cancel = document.createElement('button'); cancel.type='button'; cancel.className='secondary'; cancel.textContent='Cancel';
    const close = document.createElement('button'); close.type='button'; close.className='creation-close'; close.textContent='×'; close.setAttribute('aria-label','Close dialog');
    const content = creation.querySelector('.creation-content');
    dialog.append(heading,close,content,cancel); document.body.append(dialog); creation.remove();
    const form=dialog.querySelector('form');
    const error=document.createElement('p');error.className='settings-error';error.setAttribute('role','alert');error.hidden=true;content.prepend(error);
    form.addEventListener('submit',async event=>{
      // Local invitations may return a private setup page instead of a redirect.
      if(form.classList.contains('add-user-form'))return;
      event.preventDefault();const button=form.querySelector('button[type=submit]');if(button.disabled)return;
      const label=button.textContent;button.disabled=true;button.textContent='Adding…';error.hidden=true;
      try {
        const response=await fetch(form.action,{method:'POST',body:new FormData(form),credentials:'same-origin'});
        const page=new DOMParser().parseFromString(await response.text(),'text/html');
        const problem=page.querySelector('.settings-error');
        if(!response.ok || problem || new URL(response.url).pathname!==location.pathname)throw Error(problem?.textContent.trim() || 'Could not confirm the request. Please try again.');
        location.assign(response.url);
      }catch(failure){error.textContent=failure.message;error.hidden=false;button.disabled=false;button.textContent=label;}
    });
    const values=()=>JSON.stringify([...form.elements].map(x=>[x.value,x.checked])); let initial=values();
    const dismiss=()=>{if(values()!==initial){document.dispatchEvent(new CustomEvent('keep-confirm-discard',{detail:()=>{form.reset();dialog.close();}}));return;}dialog.close();};
    open.addEventListener('click',()=>{initial=values();dialog.showModal();heading.focus({preventScroll:true});});
    cancel.addEventListener('click',dismiss);
    close.addEventListener('click',dismiss);
    dialog.addEventListener('cancel',event=>{event.preventDefault();dismiss();});
    dialog.addEventListener('close',()=>open.focus());
    open.disabled=false;
  }
  const select = document.querySelector('.activity-mobile-filter select');
  select?.addEventListener('change', () => { location.href = select.value; });
  for (const card of document.querySelectorAll('.recipient-row')) {
    const editor = card.querySelector('.user-editor');
    if (!editor.hidden) { const toggle = card.querySelector('[data-user-toggle]'); toggle.setAttribute('aria-expanded','true'); toggle.querySelector('[data-edit-label]').textContent='Close'; }
  }
})();
