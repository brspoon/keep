const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync('static/keep-select.js', 'utf8');
function fixture(texts=['30 days','90 days','365 days','Never expires'], {disabled=false, disabledOptions=[], grouped=false, inDialog=false}={}) {
  class Element {
    constructor(tag='div') { this.tagName=tag.toUpperCase(); this.children=[]; this.dataset={}; this.attrs={}; this.listeners={}; this.hidden=false; this.style={}; this.textContent=''; this.isConnected=true;
      const classes=new Set(); this.classList={add:v=>classes.add(v),toggle:(v,on)=>on?classes.add(v):classes.delete(v)}; }
    set innerHTML(_) { throw Error('Option text must never be parsed as HTML'); }
    append(...children) { for(const child of children) { child.parentElement=this; this.children.push(child); } }
    before(child) { this.parentElement.append(child); }
    remove() { this.isConnected=false; if(this.parentElement) this.parentElement.children=this.parentElement.children.filter(c=>c!==this); }
    replaceChildren(...children) { this.children=[]; this.append(...children); }
    setAttribute(k,v) { this.attrs[k]=String(v); }
    getAttribute(k) { return this.attrs[k] || null; }
    removeAttribute(k) { delete this.attrs[k]; }
    addEventListener(k,v) { (this.listeners[k] ||= []).push(v); }
    dispatchEvent(e) { e.target ||= this; (this.listeners[e.type] || []).forEach(fn=>fn(e)); return true; }
    focus() { document.activeElement=this; }
    scrollIntoView() {}
    closest(selector) { return selector === 'dialog' ? modal : null; }
    contains(node) { return this===node || this.children.some(c=>c.contains(node)); }
    querySelectorAll(selector) { return this.children.filter(c=>selector==='select'?c.tagName==='SELECT':c.className==='keep-select-group'); }
    getBoundingClientRect() { return {left:290,top:100,bottom:146,width:112}; }
  }
  const document=new Element(), body=new Element('body'), select=new Element('select'), form=new Element('form'), modal=inDialog ? new Element('dialog') : null;
  document.body=body; document.createElement=tag=>new Element(tag); document.getElementById=()=>null; document.querySelectorAll=()=>[select];
  if(modal) { body.append(modal); modal.append(select); } else body.append(select);
  select.form=form; select.name='expiry'; select.labels=[]; select.disabled=disabled; select.required=false; select.validity={valid:true}; select.size=0;
  select.options=texts.map((text,i)=> { const option=new Element('option'); option.textContent=text; option.value=String(i); option.disabled=disabledOptions.includes(i); option.parentElement=grouped && i===2 ? {tagName:'OPTGROUP',label:'Unavailable',disabled:true} : select; return option; });
  let selected=1;
  Object.defineProperty(select,'selectedIndex',{get:()=>selected,set:v=>{selected=v;}});
  Object.defineProperty(select,'value',{get:()=>select.options[selected].value,set:v=>{selected=select.options.findIndex(o=>o.value===v);}});
  select.options.forEach((option,i)=>Object.defineProperty(option,'selected',{get:()=>i===selected}));
  const window=new Element(); window.innerWidth=375; window.innerHeight=700;
  const timers=[], observers=[]; let poll;
  class MutationObserver { constructor(callback) { this.callback=callback; observers.push(this); } observe() {} }
  class Event { constructor(type,props={}) { this.type=type; Object.assign(this,props); } }
  vm.runInNewContext(source,{document,window,MutationObserver,Event,Date,setInterval:fn=>{poll=fn;},setTimeout:fn=>timers.push(fn)});
  const parent=modal || body, wrapper=parent.children.find(c=>c.className==='keep-select'), trigger=wrapper.children[1], panel=parent.children.find(c=>c.className==='keep-select-panel'), search=panel.children[0], list=panel.children[1];
  const fire=(node,type,props={})=>{const event={type,target:node,preventDefault(){this.prevented=true;},stopPropagation(){},...props}; node.dispatchEvent(event); return event;};
  return {select,trigger,panel,search,list,form,document,modal,body,fire,poll:()=>poll(),flush:()=>timers.splice(0).forEach(fn=>fn()),observers};
}
test('enhancement retains enabled native form value and displays text safely',()=>{
  const f=fixture(['<img src=x onerror=alert(1)>','90 days']);
  assert.equal(f.select.disabled,false); assert.equal(f.select.value,'1'); assert.equal(f.select.tabIndex,-1);
  f.fire(f.trigger,'click');
  assert.equal(f.list.children[0].textContent,'<img src=x onerror=alert(1)>');
  assert.equal(f.trigger.attrs['aria-expanded'],'true');
  assert.equal(f.trigger.attrs['aria-controls'],f.list.id);
  assert.equal(f.panel.style.width,'240px'); assert.equal(f.panel.style.left,'127px');
});
test('arrows skip disabled options and Enter emits one bubbling native change only when value changes',()=>{
  const f=fixture(undefined,{disabledOptions:[2]}); const changes=[];
  f.select.addEventListener('change',e=>changes.push(e));
  f.fire(f.trigger,'keydown',{key:'ArrowDown'}); // Open at current selection.
  f.fire(f.trigger,'keydown',{key:'ArrowDown'}); // Skip 365 days.
  f.fire(f.trigger,'keydown',{key:'Enter'});
  assert.equal(f.select.selectedIndex,3); assert.equal(changes.length,1); assert.equal(changes[0].bubbles,true); assert.equal(changes[0].target,f.select);
  f.fire(f.trigger,'click'); f.fire(f.trigger,'keydown',{key:'Enter'});
  assert.equal(changes.length,1); assert.equal(f.panel.hidden,true);
});
test('Home, End, Space, Escape and typeahead navigate without premature changes',()=>{
  const f=fixture();
  f.fire(f.trigger,'keydown',{key:' '}); f.fire(f.trigger,'keydown',{key:'End'});
  assert.match(f.trigger.attrs['aria-activedescendant'],/option-3$/);
  f.fire(f.trigger,'keydown',{key:'Home'}); assert.match(f.trigger.attrs['aria-activedescendant'],/option-0$/);
  f.fire(f.trigger,'keydown',{key:'N'}); assert.match(f.trigger.attrs['aria-activedescendant'],/option-3$/);
  f.fire(f.trigger,'keydown',{key:'Escape'}); assert.equal(f.select.selectedIndex,1); assert.equal(f.panel.hidden,true);
});
test('disabled managed select and disabled optgroup cannot be committed',()=>{
  const f=fixture(undefined,{disabled:true}); f.fire(f.trigger,'click'); assert.equal(f.panel.hidden,true); assert.equal(f.trigger.disabled,true);
  const g=fixture(undefined,{grouped:true}); g.fire(g.trigger,'click'); g.fire(g.list.children.find(n=>n.id?.endsWith('option-2')),'click'); assert.equal(g.select.selectedIndex,1);
});
test('external changes, silent assignments and native reset synchronize without synthetic change',()=>{
  const f=fixture(); let count=0; f.select.addEventListener('change',()=>count++);
  f.select.value='0'; f.poll(); assert.equal(f.trigger.children[0].textContent,'30 days'); assert.equal(count,0);
  f.select.value='3'; f.select.dispatchEvent({type:'change'}); assert.equal(f.trigger.children[0].textContent,'Never expires'); assert.equal(count,1);
  f.fire(f.trigger,'click'); f.fire(f.form,'reset'); f.select.selectedIndex=1; f.flush();
  assert.equal(f.trigger.children[0].textContent,'90 days'); assert.equal(f.panel.hidden,true); assert.equal(count,1);
});
test('large lists search and keyboard commit while Tab, outside click and outside focus close',()=>{
  const f=fixture(Array.from({length:20},(_,i)=>`Account ${i}`));
  f.fire(f.trigger,'click'); assert.equal(f.search.hidden,false); assert.equal(f.document.activeElement,f.search);
  f.search.value='Account 17'; f.fire(f.search,'input'); assert.equal(f.list.children.filter(n=>!n.hidden).length,1);
  f.fire(f.search,'keydown',{key:'Enter'}); assert.equal(f.select.selectedIndex,17);
  f.fire(f.trigger,'click'); f.fire(f.search,'keydown',{key:'Tab'}); assert.equal(f.panel.hidden,true); assert.equal(f.document.activeElement,f.trigger);
  f.fire(f.trigger,'click'); f.fire(f.document,'pointerdown',{target:f.form}); assert.equal(f.panel.hidden,true);
  f.fire(f.trigger,'click'); f.fire(f.document,'focusin',{target:f.form}); assert.equal(f.panel.hidden,true);
});
test('dialog selects keep their popup in the modal, support keyboard and click selection, and close with the dialog',()=>{
  const f=fixture(undefined,{inDialog:true});
  assert.equal(f.panel.parentElement,f.modal);
  assert.equal(f.body.children.includes(f.panel),false);
  f.fire(f.trigger,'click');
  assert.equal(f.panel.hidden,false);
  assert.equal(f.panel.style.left,'127px');
  f.fire(f.list.children[3],'click');
  assert.equal(f.select.selectedIndex,3); assert.equal(f.panel.hidden,true);
  f.fire(f.trigger,'keydown',{key:'ArrowDown'});
  f.fire(f.trigger,'keydown',{key:'Home'});
  f.fire(f.trigger,'keydown',{key:'Enter'});
  assert.equal(f.select.selectedIndex,0);
  f.fire(f.trigger,'click'); f.fire(f.trigger,'keydown',{key:'Escape'});
  assert.equal(f.panel.hidden,true);
  f.fire(f.trigger,'click'); f.fire(f.modal,'close');
  assert.equal(f.panel.hidden,true); assert.equal(f.trigger.attrs['aria-expanded'],'false');
});
