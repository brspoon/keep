const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(groups, {mobile=false,reduced=true,observerAvailable=true,capture=true,moveLosesFocus=false,
  viewportHeight=800,viewportOffset=0,scrollY=250}={}) {
  let document,window,nextFrame=0,offset='120px';
  const frames=new Map(),observers=[],scrolls=[];
  class Element {
    constructor(tag='div',className='',text='') {
      this.tagName=tag.toUpperCase(); this.className=className; this._text=text;
      this.children=[]; this.parentElement=null; this.dataset={}; this.attrs={}; this.listeners={};
      this.hidden=false; this.disabled=false; this.value=''; this.tabIndex=0; this.captured=new Set();
      this.style={setProperty(name,value){this[name]=value;},removeProperty(name){delete this[name];}};
      this.classList={contains:name=>this.className.split(/\s+/).includes(name),
        add:(...names)=>{this.className=[...new Set([...this.className.split(/\s+/).filter(Boolean),...names])].join(' ');},
        remove:(...names)=>{this.className=this.className.split(/\s+/).filter(name=>!names.includes(name)).join(' ');},
        toggle:(name,force)=>{const on=force===undefined?!this.classList.contains(name):Boolean(force);on?this.classList.add(name):this.classList.remove(name);return on;}};
      this.docTop=null; this.rect={top:0,left:740,width:44,height:44};
      if(!capture) this.setPointerCapture=undefined;
    }
    set innerHTML(_) {throw new Error('Collection and title content must remain text');}
    get textContent(){return this._text+this.children.map(child=>child.textContent).join('');}
    set textContent(value){this._text=String(value);this.replaceChildren();}
    get isConnected(){return this===document?.body||this===document?.documentElement||Boolean(this.parentElement?.isConnected);}
    get ownerDocument(){return document;}
    get firstElementChild(){return this.children[0]||null;}
    get lastElementChild(){return this.children.at(-1)||null;}
    get offsetHeight(){return this.getBoundingClientRect().height;}
    get clientHeight(){return this.getBoundingClientRect().height;}
    get offsetWidth(){return this.getBoundingClientRect().width;}
    append(...children){children.forEach(child=>{if(moveLosesFocus&&child.isConnected&&child.contains(document.activeElement))document.activeElement=document.body;child.remove();child.parentElement=this;this.children.push(child);});}
    appendChild(child){this.append(child);return child;}
    replaceChildren(...children){this.children.forEach(child=>{child.parentElement=null;});this.children=[];this.append(...children);}
    remove(){if(this.parentElement){this.parentElement.children=this.parentElement.children.filter(child=>child!==this);this.parentElement=null;}}
    setAttribute(name,value){this.attrs[name]=String(value);if(name==='class')this.className=String(value);if(name==='id')this.id=String(value);if(name==='tabindex')this.tabIndex=Number(value);
      if(name.startsWith('data-'))this.dataset[name.slice(5).replace(/-([a-z])/g,(_,char)=>char.toUpperCase())]=String(value);}
    getAttribute(name){return name==='class'?this.className:name==='id'?this.id||null:this.attrs[name]??null;}
    hasAttribute(name){return this.getAttribute(name)!==null;}
    removeAttribute(name){delete this.attrs[name];}
    matches(selector){
      if(selector.includes(','))return selector.split(',').some(part=>this.matches(part.trim()));
      if(selector.includes(' '))return this.matches(selector.split(' ').at(-1));
      if(selector.includes(':not([hidden])'))return !this.hidden&&this.matches(selector.replace(':not([hidden])',''));
      const tag=selector.match(/^[a-z][a-z0-9-]*/i)?.[0];if(tag&&this.tagName!==tag.toUpperCase())return false;
      for(const [,name] of selector.matchAll(/\.([a-z0-9_-]+)/gi))if(!this.classList.contains(name))return false;
      for(const [,name,value] of selector.matchAll(/\[([^=\]]+)(?:=["']?([^\]"']+)["']?)?\]/g)){
        if(name==='hidden'){if(!this.hidden)return false;}
        else if(!this.hasAttribute(name)||value!==undefined&&this.getAttribute(name)!==value)return false;}
      if(selector.startsWith('#')&&this.id!==selector.slice(1))return false;
      return Boolean(tag||/[.#\[]/.test(selector));}
    querySelectorAll(selector){return this.children.flatMap(child=>[...(child.matches(selector)?[child]:[]),...child.querySelectorAll(selector)]);}
    querySelector(selector){return this.querySelectorAll(selector)[0]||null;}
    closest(selector){return this.matches(selector)?this:this.parentElement?.closest(selector)||null;}
    contains(node){return node===this||this.children.some(child=>child.contains(node));}
    addEventListener(type,handler){(this.listeners[type]||=[]).push(handler);}
    removeEventListener(type,handler){this.listeners[type]=(this.listeners[type]||[]).filter(item=>item!==handler);}
    fire(type,extra={}){
      const event={type,target:this,button:0,pointerId:1,pointerType:'touch',isPrimary:true,clientX:762,clientY:200,defaultPrevented:false,stopped:false,
        preventDefault(){this.defaultPrevented=true;},stopPropagation(){this.stopped=true;},...extra};
      let current=this;do{event.currentTarget=current;[...(current.listeners[type]||[])].forEach(handler=>handler(event));
        current=!event.stopped&&extra.bubbles?current.parentElement:null;}while(current);
      if(extra.bubbles&&!event.stopped&&this!==document)document.deliver(type,event);return event;}
    focus(options){const previous=document.activeElement;if(previous!==this)previous?.fire('focusout',{relatedTarget:this,bubbles:true});
      document.activeElement=this;this.focusOptions=options;this.focusCount=(this.focusCount||0)+1;this.fire('focusin',{relatedTarget:previous,bubbles:true});}
    blur(){const previous=document.activeElement;document.activeElement=document.body;previous?.fire('focusout',{relatedTarget:document.body,bubbles:true});}
    scrollIntoView(options){this.scrollOptions=options;}
    setPointerCapture(pointerId){if(capture==='throw')throw new Error('Pointer capture unavailable');this.captured.add(pointerId);}
    hasPointerCapture(pointerId){return this.captured.has(pointerId);}
    releasePointerCapture(pointerId){this.captured.delete(pointerId);this.fire('lostpointercapture',{pointerId});}
    getBoundingClientRect(){let top=this.docTop===null?this.rect.top:this.docTop-window.scrollY,height=this.rect.height;
      if(this.classList.contains('section-header')){const section=this.parentElement;top=Math.min(Math.max(top,parseFloat(offset)||80),section.docTop+section.rect.height-window.scrollY-height);}
      if(this.classList.contains('alphabet-side-navigation'))top=parseFloat(this.style.top)||0;
      if(this.classList.contains('alphabet-scrub-track')){top=this.parentElement.getBoundingClientRect().top;height=parseFloat(this.style.height)||200;}
      if(this.classList.contains('alphabet-scrub-handle')){const track=this.parentElement.getBoundingClientRect();top=track.top+(parseFloat(this.style.top)||0);height=56;}
      return {top,height,left:this.rect.left,width:this.rect.width,right:this.rect.left+this.rect.width,bottom:top+height};}
    getClientRects(){return this.hidden||!this.isConnected?[]:[this.getBoundingClientRect()];}
  }
  const root=new Element('html'),body=new Element('body','library-ui'),view=new Element('div','media-view');
  document=new Element('document');document.documentElement=root;document.body=body;document.activeElement=body;
  document.deliver=(type,event)=>[...(document.listeners[type]||[])].forEach(handler=>handler(event));
  document.createElement=tag=>new Element(tag);document.createElementNS=(_,tag)=>new Element(tag);
  document.querySelectorAll=selector=>[...(body.matches(selector)?[body]:[]),...body.querySelectorAll(selector)];
  document.querySelector=selector=>document.querySelectorAll(selector)[0]||null;document.getElementById=id=>document.querySelector('#'+id);
  body.append(view);
  const sections=groups.map((group,index)=>{
    const section=new Element('section'),header=new Element('div','section-header'),title=new Element('h2','',group.name),grid=new Element('div','grid');
    section.setAttribute('data-alphabet-section','');section.id=`collection-${index+1}`;section.docTop=group.top??(200+index*2000);section.rect.height=group.height??1750;
    header.docTop=section.docTop;header.rect.height=40;title.docTop=section.docTop;header.append(title);
    section.cards=group.titles.map((value,cardIndex)=>{const card=new Element('article','card');card.dataset.title=typeof value==='string'?value:value.title;
      card.hidden=Boolean(value.hidden);card.docTop=section.docTop+100+cardIndex*250;card.rect.height=220;card.append(new Element('div','title',card.dataset.title));return card;});
    grid.append(...section.cards);section.append(header,grid);section.hidden=Boolean(group.hidden);return section;});
  view.append(...sections);
  const search=new Element('input'),clear=new Element('button'),scope=new Element('button');search.id='media-search';clear.id='search-clear';scope.setAttribute('data-keep-scope','mine');body.append(search,clear,scope);
  window=new Element('window');window.scrollY=scrollY;window.innerHeight=viewportHeight;window.innerWidth=mobile?390:1200;
  window.visualViewport=new Element('viewport');window.visualViewport.height=viewportHeight;window.visualViewport.offsetTop=viewportOffset;
  const media=new Map();window.matchMedia=query=>{if(!media.has(query)){const match=new Element('media');match.matches=query.includes('max-width')?mobile:reduced;media.set(query,match);}return media.get(query);};
  window.scrollTo=(options,y)=>{const top=typeof options==='object'?options.top:y;scrolls.push({top,behavior:typeof options==='object'?options.behavior:'auto',focus:document.activeElement});window.scrollY=top;window.fire('scroll');};
  class MutationObserver{constructor(callback){this.callback=callback;observers.push(this);}observe(target,options){this.target=target;this.options=options;}disconnect(){}}
  if(observerAvailable)window.MutationObserver=MutationObserver;
  vm.runInNewContext(fs.readFileSync('static/keep-alphabet.js','utf8'),{document,window,MutationObserver,requestAnimationFrame:callback=>{frames.set(++nextFrame,callback);return nextFrame;},cancelAnimationFrame:id=>frames.delete(id),
    getComputedStyle:element=>({getPropertyValue:name=>name==='--browse-offset'?offset:'',height:`${element.getBoundingClientRect().height}px`}),parseFloat,performance:{now:()=>0}});
  const flush=()=>{let count=0;while(frames.size){if(++count>100)throw new Error('Animation frame loop');const batch=[...frames];frames.clear();batch.forEach(([,fn])=>fn());}};
  const side=()=>document.querySelector('.alphabet-side-navigation'),buttons=()=>side()?.querySelectorAll('.alphabet-side-letter')||[];
  return {document,window,sections,search,clear,scope,view,frames,observers,scrolls,flush,side,visible:()=>buttons().filter(button=>!button.hidden).sort((a,b)=>Number(a.style.order)-Number(b.style.order)).map(button=>button.dataset.letter),
    button:letter=>buttons().find(button=>button.dataset.letter===letter),handle:()=>side()?.querySelector('.alphabet-scrub-handle'),track:()=>side()?.querySelector('.alphabet-scrub-track'),bubble:()=>side()?.querySelector('.alphabet-scrub-bubble'),
    setOffset:value=>{offset=value;},scroll:top=>{window.scrollY=top;window.fire('scroll');flush();},
    setMobile:matches=>{mobile=matches;window.innerWidth=matches?390:1200;const match=window.matchMedia('(max-width: 700px)');match.matches=matches;match.fire('change',{matches});window.fire('resize');flush();},
    pointer:(type,extra={})=>document.fire(type,{pointerId:1,pointerType:'touch',isPrimary:true,...extra})};
}
const movies=()=>[{name:'Movies',titles:['Alpha','Another','Beta','Zulu']}];
function beginDrag(f,extra={}){const handle=f.handle(),rect=handle.getBoundingClientRect();return handle.fire('pointerdown',{clientY:rect.top+rect.height/2,...extra});}

test('one page index follows the visible section and preserves card order',()=>{
  const f=fixture([...movies(),{name:'Shows',titles:['Charlie','Zulu']}]);f.flush();
  assert.equal(f.document.querySelectorAll('.alphabet-side-navigation').length,1);assert.equal(f.side().parentElement,f.document.body);assert.deepEqual(f.visible(),['A','B','Z']);
  const before=[...f.sections[0].cards];f.button('B').fire('click');assert.equal(f.document.activeElement,f.sections[0].cards[2]);assert.equal(f.sections[0].cards[2].focusOptions.preventScroll,true);assert.deepEqual(f.sections[0].cards,before);
  f.search.focus();f.scroll(2200);assert.deepEqual(f.visible(),['C','Z']);assert.match(f.button('C').getAttribute('aria-label'),/Shows/);
  f.button('C').fire('click');assert.equal(f.document.activeElement,f.sections[1].cards[0]);
});
test('filter and scope refresh select the first visible matching card',()=>{
  const f=fixture(movies());f.flush();f.sections[0].cards[0].hidden=true;f.sections[0].cards[2].hidden=true;f.search.fire('input');f.flush();assert.deepEqual(f.visible(),['A','Z']);
  f.button('A').fire('click');assert.equal(f.document.activeElement,f.sections[0].cards[1]);f.sections[0].hidden=true;f.scope.fire('click');f.flush();assert.equal(f.side().hidden,true);
  f.sections[0].hidden=false;f.sections[0].cards.forEach(card=>{card.hidden=false;});f.clear.fire('click');f.flush();assert.equal(f.side().hidden,false);assert.deepEqual(f.visible(),['A','B','Z']);
});
test('literal ASCII initials and other titles preserve the first visible target',()=>{
  const f=fixture([{name:'Library',titles:['2001','"Alpha"','a movie',' The movie','Éclair','Σειρά','中文']}]);f.flush();assert.deepEqual(f.visible(),['#','A','T']);
  f.button('#').fire('click');assert.equal(f.document.activeElement,f.sections[0].cards[0]);f.sections[0].cards[0].hidden=true;f.sections[0].cards[1].hidden=true;f.search.fire('input');f.flush();
  f.button('#').fire('click');assert.equal(f.document.activeElement,f.sections[0].cards[4]);
});
test('desktop arrow and edge keys navigate available letters without media actions',()=>{
  const f=fixture(movies());f.flush();f.button('A').focus();assert.equal(f.button('A').fire('keydown',{key:'ArrowDown'}).defaultPrevented,true);assert.equal(f.document.activeElement,f.button('B'));
  f.button('B').fire('keydown',{key:'End'});assert.equal(f.document.activeElement,f.button('Z'));f.button('Z').fire('keydown',{key:'Home'});assert.equal(f.document.activeElement,f.button('A'));assert.equal(f.scrolls.length,0);
});
test('focused desktop index keeps its collection context until focus leaves',()=>{
  const f=fixture([...movies(),{name:'Shows',titles:['Charlie','Delta']}]);f.flush();f.button('A').focus();f.scroll(2300);assert.deepEqual(f.visible(),['A','B','Z']);
  f.search.focus();f.window.fire('scroll');f.flush();assert.deepEqual(f.visible(),['C','D']);
});
test('wheel scrolling outside the index releases keyboard context while wheel inside keeps it',()=>{
  const f=fixture([...movies(),{name:'Shows',titles:['Charlie','Delta']}]);f.flush();f.button('A').focus();f.scroll(2300);assert.deepEqual(f.visible(),['A','B','Z']);
  f.document.fire('wheel',{target:f.button('A')});f.flush();assert.deepEqual(f.visible(),['A','B','Z']);
  f.document.fire('wheel',{target:f.search});f.flush();assert.deepEqual(f.visible(),['C','D']);
});
test('mobile slider keys jump with handle focus and explicitly commit to a card',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();const handle=f.handle();assert.equal(handle.getAttribute('role'),'slider');handle.focus();
  handle.fire('keydown',{key:'End'});f.flush();assert.equal(f.document.activeElement,handle);assert.match(handle.getAttribute('aria-valuetext'),/Z/);assert.equal(f.scrolls.at(-1).behavior,'instant');
  handle.fire('keydown',{key:'Enter'});f.flush();assert.equal(f.document.activeElement,f.sections[0].cards[3]);handle.focus();handle.fire('keydown',{key:'Home'});handle.fire('keydown',{key:' '});f.flush();assert.equal(f.document.activeElement,f.sections[0].cards[0]);
});
test('drag scrubs without card focus, locks its section, and commits only on release',()=>{
  const f=fixture([...movies(),{name:'Shows',titles:['Charlie','Delta']}],{mobile:true});f.flush();assert.equal(beginDrag(f).defaultPrevented,true);assert.equal(f.bubble().hidden,false);assert.equal(f.handle().captured.has(1),true);
  f.window.scrollY=2300;f.window.fire('scroll');f.flush();assert.deepEqual(f.visible(),['A','B','Z']);f.pointer('pointermove',{clientY:10000});f.flush();assert.equal(f.bubble().textContent,'Z');assert.equal(f.document.activeElement,f.document.body);assert.equal(f.scrolls.at(-1).behavior,'instant');
  f.pointer('pointerup',{clientY:10000});f.flush();assert.equal(f.bubble().hidden,true);assert.equal(f.document.activeElement,f.sections[0].cards[3]);assert.equal(f.sections[0].cards[3].focusCount,1);assert.equal(f.handle().captured.has(1),false);
});
test('drag coordinates clamp to the first and last available letters',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();beginDrag(f);f.pointer('pointermove',{clientY:-10000});f.flush();assert.equal(f.bubble().textContent,'A');f.pointer('pointermove',{clientY:10000});f.flush();assert.equal(f.bubble().textContent,'Z');f.pointer('pointerup',{clientY:10000});f.flush();assert.equal(f.document.activeElement,f.sections[0].cards[3]);
});
test('off-center handle grabs do not immediately select another initial',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();const handle=f.handle();handle.focus();handle.fire('keydown',{key:'ArrowDown'});f.flush();const before=handle.getAttribute('aria-valuenow'),rect=handle.getBoundingClientRect();
  beginDrag(f,{clientY:rect.bottom-2});f.flush();assert.equal(handle.getAttribute('aria-valuenow'),before);f.pointer('pointermove',{clientY:rect.bottom-2});f.flush();assert.equal(handle.getAttribute('aria-valuenow'),before);f.pointer('pointercancel');f.flush();assert.equal(f.document.activeElement,handle);
});
test('secondary pointers and nonprimary mouse buttons cannot hijack scrubbing',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();beginDrag(f,{isPrimary:false,pointerId:2});assert.equal(f.bubble().hidden,true);beginDrag(f,{pointerType:'mouse',button:2});assert.equal(f.bubble().hidden,true);
  beginDrag(f);const before=f.bubble().textContent;f.pointer('pointermove',{pointerId:2,clientY:10000});f.flush();assert.equal(f.bubble().textContent,before);f.pointer('pointerup',{pointerId:2});f.flush();assert.equal(f.bubble().hidden,false);f.pointer('pointercancel',{pointerId:1});f.flush();assert.equal(f.bubble().hidden,true);
});
test('pointer cancellation and lost capture never commit media focus',()=>{
  for(const type of ['pointercancel','lostpointercapture']){const f=fixture(movies(),{mobile:true});f.flush();beginDrag(f);f.pointer('pointermove',{clientY:10000});f.flush();type==='lostpointercapture'?f.handle().fire(type,{pointerId:1}):f.pointer(type);f.flush();assert.equal(f.bubble().hidden,true);assert.equal(f.document.activeElement,f.document.body);f.pointer('pointerup');f.flush();assert.equal(f.document.activeElement,f.document.body);}
});
test('document pointer events support scrubbing when capture is unavailable',()=>{
  for(const capture of [false,'throw']){const f=fixture(movies(),{mobile:true,capture});f.flush();assert.doesNotThrow(()=>beginDrag(f));f.pointer('pointermove',{clientY:10000});f.flush();f.pointer('pointerup',{clientY:10000});f.flush();assert.equal(f.document.activeElement,f.sections[0].cards[3]);}
});
test('changing letters or hiding the section cancels a drag instead of using stale media',()=>{
  for(const change of ['letter','section']){const f=fixture(movies(),{mobile:true});f.flush();beginDrag(f);f.pointer('pointermove',{clientY:10000});f.flush();if(change==='letter')f.sections[0].cards[3].hidden=true;else f.sections[0].hidden=true;f.search.fire('input');f.flush();assert.equal(f.bubble().hidden,true);f.pointer('pointerup',{clientY:10000});f.flush();assert.equal(f.document.activeElement,f.document.body);}
});
test('removing the first card of a drag letter safely retargets its remaining card',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();beginDrag(f);f.sections[0].cards[0].remove();f.window.KeepAlphabet.refresh();f.flush();f.pointer('pointermove',{clientY:-1000});f.flush();f.pointer('pointerup',{clientY:-1000});f.flush();assert.equal(f.document.activeElement,f.sections[0].cards[1]);
});
test('visualViewport layout changes rebase a drag without changing the selected initial',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();const handle=f.handle();handle.focus();handle.fire('keydown',{key:'ArrowDown'});f.flush();
  const before=handle.getAttribute('aria-valuenow'),rect=handle.getBoundingClientRect(),lastY=rect.top+rect.height/2;
  beginDrag(f,{clientY:lastY});f.window.visualViewport.offsetTop=80;f.window.visualViewport.height=400;f.window.visualViewport.fire('resize');f.flush();
  assert.equal(f.bubble().hidden,false);assert.equal(handle.getAttribute('aria-valuenow'),before);f.pointer('pointermove',{clientY:lastY});f.flush();assert.equal(handle.getAttribute('aria-valuenow'),before);
  f.pointer('pointercancel');f.flush();assert.equal(f.document.activeElement,handle);
});
test('switching to desktop cancels an active mobile pointer session',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();beginDrag(f);f.setMobile(false);assert.equal(f.bubble().hidden,true);f.pointer('pointerup');f.flush();assert.equal(f.document.activeElement,f.document.body);
});
test('removing the keyboard-selected letter preserves a reachable desktop tab stop',()=>{
  const f=fixture(movies());f.flush();f.button('A').focus();f.button('A').fire('keydown',{key:'ArrowDown'});assert.equal(f.document.activeElement,f.button('B'));
  f.sections[0].cards[2].hidden=true;f.search.fire('input');f.flush();
  assert.equal(f.side().querySelectorAll('.alphabet-side-letter').filter(button=>!button.hidden&&button.tabIndex===0).length,1);
});
test('reordering the letter nodes preserves an available keyboard selection if the browser drops move focus',()=>{
  const f=fixture(movies(),{moveLosesFocus:true});f.flush();f.button('A').focus();f.button('A').fire('keydown',{key:'ArrowDown'});const focused=f.button('B');
  f.sections[0].cards[3].hidden=true;f.search.fire('input');f.flush();assert.equal(f.document.activeElement,focused);assert.equal(focused.tabIndex,0);assert.equal(focused.focusOptions.preventScroll,true);
});
test('a mobile rail waits below an intro heading, freezes during scrubbing, then expands after release',()=>{
  const f=fixture([{...movies()[0],top:500}],{mobile:true,viewportHeight:844,scrollY:0});f.flush();
  const header=f.sections[0].querySelector('.section-header').getBoundingClientRect(),before=f.track().getBoundingClientRect();
  assert.equal(before.top,header.bottom+8);assert.ok(before.bottom<=844-88);assert.equal(f.side().hidden,false);
  beginDrag(f);f.pointer('pointermove',{clientY:before.bottom});f.flush();assert.equal(f.bubble().textContent,'Z');assert.ok(f.window.scrollY>0);
  const held=f.track().getBoundingClientRect();assert.equal(held.top,before.top);assert.equal(held.height,before.height);assert.equal(f.document.activeElement,f.document.body);
  f.pointer('pointerup',{clientY:before.bottom});f.flush();assert.equal(f.document.activeElement,f.sections[0].cards[3]);
  const after=f.track().getBoundingClientRect();assert.equal(after.top,f.sections[0].querySelector('.section-header').getBoundingClientRect().bottom+8);assert.ok(after.height>before.height);assert.ok(after.bottom<=844-88);
});
test('a near-bottom bare heading hides the mobile rail until its titles have usable space',()=>{
  const f=fixture([{...movies()[0],top:740}],{mobile:true,viewportHeight:844,scrollY:0});f.flush();
  assert.equal(f.side().hidden,true);assert.equal(f.bubble().hidden,true);beginDrag(f);assert.equal(f.bubble().hidden,true);assert.equal(f.scrolls.length,0);
  f.scroll(500);assert.equal(f.side().hidden,false);assert.ok(f.track().getBoundingClientRect().height>=56);
});
test('insufficient mobile visual-viewport space hides the rail without starting a stale pointer session',()=>{
  const f=fixture(movies(),{mobile:true,viewportHeight:260,viewportOffset:60});f.flush();
  assert.equal(f.side().hidden,true);beginDrag(f);assert.equal(f.bubble().hidden,true);assert.equal(f.scrolls.length,0);
  f.window.visualViewport.height=600;f.window.visualViewport.fire('resize');f.flush();assert.equal(f.side().hidden,false);
  const rect=f.track().getBoundingClientRect();assert.ok(rect.top>=60+120+8);assert.ok(rect.bottom<=60+600-88);
});
test('desktop and mobile indices follow first appearances when the other-title bucket occurs last',()=>{
  for(const mobile of [false,true]){const f=fixture([{name:'Shows',titles:['Alpha','Zulu','Éclair']}],{mobile});f.flush();assert.deepEqual(f.visible(),['A','Z','#']);
    assert.deepEqual(f.side().querySelectorAll('.alphabet-side-letter').filter(button=>!button.hidden).map(button=>button.dataset.letter),['A','Z','#']);
    if(mobile){f.handle().focus();f.handle().fire('keydown',{key:'End'});f.handle().fire('keydown',{key:'Enter'});}else{f.button('A').focus();f.button('A').fire('keydown',{key:'End'});assert.equal(f.document.activeElement,f.button('#'));f.button('#').fire('click');}
    f.flush();assert.equal(f.document.activeElement,f.sections[0].cards[2]);}
});
test('the first title on the nearest visible grid row determines the current letter',()=>{
  for(const mobile of [false,true]){const f=fixture([{name:'Movies',titles:['Alpha','Beta','Beta again','Zulu']}],{mobile});
    const cards=f.sections[0].cards;cards[1].docTop=cards[0].docTop;cards[2].docTop=600;
    f.window.KeepAlphabet.refresh();f.flush();assert.equal(f.button('A').getAttribute('aria-current'),'location');assert.equal(f.button('B').getAttribute('aria-current'),null);
    if(mobile)assert.match(f.handle().getAttribute('aria-valuetext'),/: A$/);
    f.scroll(500);assert.equal(f.button('B').getAttribute('aria-current'),'location');assert.equal(f.button('A').getAttribute('aria-current'),null);
    if(mobile)assert.match(f.handle().getAttribute('aria-valuetext'),/: B$/);}
});
test('mobile keyboard selection survives scroll tracking when two initials share the destination row',()=>{
  const f=fixture([{name:'Movies',titles:['Alpha','X title','Y title','Z title']}],{mobile:true});
  f.sections[0].cards[3].docTop=f.sections[0].cards[2].docTop;f.window.KeepAlphabet.refresh();f.flush();
  const handle=f.handle();handle.focus();handle.fire('keydown',{key:'End'});f.flush();
  assert.match(handle.getAttribute('aria-valuetext'),/: Z$/);assert.equal(f.button('Z').getAttribute('aria-current'),'location');
  assert.equal(handle.getAttribute('aria-valuenow'),'3');assert.equal(f.document.activeElement,handle);
  handle.fire('keydown',{key:'ArrowUp'});f.flush();assert.match(handle.getAttribute('aria-valuetext'),/: Y$/);
  assert.equal(handle.getAttribute('aria-valuenow'),'2');assert.equal(f.button('Y').getAttribute('aria-current'),'location');
});
test('mobile keyboard selection returns to row tracking after focus leaves, outside wheel or selected-letter removal',()=>{
  for(const reset of ['focus','wheel','filter']){const f=fixture([{name:'Movies',titles:['Alpha','X title','Y title','Z title']}],{mobile:true});
    f.sections[0].cards[3].docTop=f.sections[0].cards[2].docTop;f.window.KeepAlphabet.refresh();f.flush();const handle=f.handle();handle.focus();handle.fire('keydown',{key:'End'});f.flush();
    assert.match(handle.getAttribute('aria-valuetext'),/: Z$/);
    if(reset==='focus')f.search.focus();else if(reset==='wheel')f.document.fire('wheel',{target:f.search});else{f.sections[0].cards[3].hidden=true;f.search.fire('input');}
    f.flush();assert.match(handle.getAttribute('aria-valuetext'),/: Y$/);assert.equal(f.button('Y').getAttribute('aria-current'),'location');
    if(reset==='filter'){assert.equal(f.button('Z').hidden,true);assert.equal(handle.getAttribute('aria-valuemax'),'2');}}
});
test('page restoration refreshes hidden cards and cancels old pointer sessions',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();beginDrag(f);f.sections[0].cards.forEach(card=>{card.hidden=true;});f.window.fire('pageshow');f.flush();assert.equal(f.side().hidden,true);assert.equal(f.bubble().hidden,true);f.pointer('pointerup');f.flush();assert.equal(f.document.activeElement,f.document.body);
});
test('blur, page exit and hidden-document transitions cancel without a later commit',()=>{
  for(const event of ['blur','pagehide','visibilitychange']){const f=fixture(movies(),{mobile:true});f.flush();beginDrag(f);f.pointer('pointermove',{clientY:10000});f.flush();
    if(event==='visibilitychange'){f.document.hidden=true;f.document.fire(event);}else f.window.fire(event);
    f.flush();assert.equal(f.bubble().hidden,true);f.pointer('pointerup');f.flush();assert.equal(f.document.activeElement,f.document.body);}
});
test('jump offsets use current sticky dimensions and reduced motion',()=>{
  const f=fixture(movies(),{reduced:false});f.flush();f.setOffset('200px');f.sections[0].querySelector('.section-header').rect.height=100;
  const expected=Math.max(0,f.sections[0].cards[2].docTop-200-100-8);f.button('B').fire('click');assert.equal(f.scrolls.at(-1).top,expected);assert.equal(f.scrolls.at(-1).behavior,'smooth');const reduced=fixture(movies());reduced.flush();reduced.button('Z').fire('click');assert.equal(reduced.scrolls.at(-1).behavior,'instant');
});
test('card removals refresh once while generated side nodes do not cause observer loops',()=>{
  const f=fixture(movies());f.flush();const observer=f.observers.find(item=>item.target===f.view);assert.ok(observer);observer.callback([{type:'childList',target:f.side(),addedNodes:[f.handle()],removedNodes:[]}]);assert.equal(f.frames.size,0);
  const removed=f.sections[0].cards[3];removed.remove();observer.callback([{type:'childList',target:f.sections[0],addedNodes:[],removedNodes:[removed]}]);observer.callback([{type:'attributes',target:f.sections[0].cards[0]}]);assert.equal(f.frames.size,1);f.flush();assert.deepEqual(f.visible(),['A','B']);
});
test('untrusted names stay text and refresh works without MutationObserver',()=>{
  const f=fixture([{name:'<img onerror=alert(1)>',titles:['Alpha']}],{observerAvailable:false});f.flush();assert.match(f.button('A').getAttribute('aria-label'),/<img onerror=/);assert.equal(f.side().querySelectorAll('img').length,0);f.sections[0].cards[0].hidden=true;f.window.fire('pageshow');f.flush();assert.equal(f.side().hidden,true);
});
test('empty media pages do not add an unused side navigation',()=>{
  const f=fixture([]);f.flush();assert.equal(f.side(),null);assert.equal(f.observers.length,0);
});
