const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(groups, {mobile=false,reduced=true,observerAvailable=true,moveLosesFocus=false,
  viewportHeight=800,viewportOffset=0,scrollY=250,headerTop=40,headerHeight=128,safeBottom=0}={}) {
  let document,window,nextFrame=0,offset='120px';
  const frames=new Map(),observers=[],resizeObservers=[],scrolls=[];
  class Element {
    constructor(tag='div',className='',text='') {
      this.tagName=tag.toUpperCase(); this.className=className; this._text=text;
      this.children=[]; this.parentElement=null; this.dataset={}; this.attrs={}; this.listeners={};
      this.hidden=false; this.disabled=false; this.value=''; this.tabIndex=0;
      this.style={setProperty(name,value){this[name]=value;},removeProperty(name){delete this[name];}};
      this.classList={contains:name=>this.className.split(/\s+/).includes(name),
        add:(...names)=>{this.className=[...new Set([...this.className.split(/\s+/).filter(Boolean),...names])].join(' ');},
        remove:(...names)=>{this.className=this.className.split(/\s+/).filter(name=>!names.includes(name)).join(' ');},
        toggle:(name,force)=>{const on=force===undefined?!this.classList.contains(name):Boolean(force);on?this.classList.add(name):this.classList.remove(name);return on;}};
      this.docTop=null; this.rect={top:0,left:740,width:44,height:44};
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
    getBoundingClientRect(){let top=this.docTop===null?this.rect.top:this.docTop-window.scrollY,height=this.rect.height;
      if(this.classList.contains('section-header')){const section=this.parentElement;top=Math.min(Math.max(top,parseFloat(offset)||80),section.docTop+section.rect.height-window.scrollY-height);}
      if(this.classList.contains('alphabet-side-navigation'))top=parseFloat(this.style.top)||0;
      return {top,height,left:this.rect.left,width:this.rect.width,right:this.rect.left+this.rect.width,bottom:top+height};}
    getClientRects(){return this.hidden||!this.isConnected?[]:[this.getBoundingClientRect()];}
  }
  const root=new Element('html'),body=new Element('body','library-ui'),view=new Element('div','media-view');
  document=new Element('document');document.documentElement=root;document.body=body;document.activeElement=body;
  document.deliver=(type,event)=>[...(document.listeners[type]||[])].forEach(handler=>handler(event));
  document.createElement=tag=>new Element(tag);document.createElementNS=(_,tag)=>new Element(tag);
  document.querySelectorAll=selector=>[...(body.matches(selector)?[body]:[]),...body.querySelectorAll(selector)];
  document.querySelector=selector=>document.querySelectorAll(selector)[0]||null;document.getElementById=id=>document.querySelector('#'+id);
  const pageHeader=new Element('header','app-header');pageHeader.docTop=headerTop;pageHeader.rect.height=headerHeight;
  body.append(pageHeader,view);
  const sections=groups.map((group,index)=>{
    const section=new Element('section'),header=new Element('div','section-header'),title=new Element('h2','',group.name),grid=new Element('div','grid');
    section.setAttribute('data-alphabet-section','');section.id=`collection-${index+1}`;section.docTop=group.top??(200+index*2000);section.rect.height=group.height??1750;
    header.docTop=section.docTop;header.rect.height=40;title.docTop=section.docTop;header.append(title);
    section.cards=group.titles.map((value,cardIndex)=>{const card=new Element('article','card');card.dataset.title=typeof value==='string'?value:value.title;
      card.hidden=Boolean(value.hidden);card.docTop=section.docTop+100+cardIndex*250;card.rect.height=220;card.append(new Element('div','title',card.dataset.title));return card;});
    grid.append(...section.cards);section.append(header,grid);section.hidden=Boolean(group.hidden);return section;});
  view.append(...sections);
  const search=new Element('input'),clear=new Element('button'),scope=new Element('button'),backToTop=new Element('button','back-to-top');
  search.id='media-search';clear.id='search-clear';backToTop.id='back-to-top';scope.setAttribute('data-keep-scope','mine');body.append(search,clear,scope,backToTop);
  window=new Element('window');window.scrollY=scrollY;window.innerHeight=viewportHeight;window.innerWidth=mobile?390:1200;
  window.visualViewport=new Element('viewport');window.visualViewport.height=viewportHeight;window.visualViewport.offsetTop=viewportOffset;
  const media=new Map();window.matchMedia=query=>{if(!media.has(query)){const match=new Element('media');match.matches=query.includes('max-width')?mobile:reduced;media.set(query,match);}return media.get(query);};
  window.scrollTo=(options,y)=>{const top=typeof options==='object'?options.top:y;scrolls.push({top,behavior:typeof options==='object'?options.behavior:'auto',focus:document.activeElement});window.scrollY=top;window.fire('scroll');};
  class MutationObserver{constructor(callback){this.callback=callback;observers.push(this);}observe(target,options){this.target=target;this.options=options;}disconnect(){}}
  class ResizeObserver{constructor(callback){this.callback=callback;this.targets=[];resizeObservers.push(this);}observe(target){this.targets.push(target);}}
  if(observerAvailable)window.MutationObserver=MutationObserver;
  window.ResizeObserver=ResizeObserver;
  vm.runInNewContext(fs.readFileSync('static/keep-alphabet.js','utf8'),{document,window,MutationObserver,ResizeObserver,requestAnimationFrame:callback=>{frames.set(++nextFrame,callback);return nextFrame;},cancelAnimationFrame:id=>frames.delete(id),
    getComputedStyle:element=>({getPropertyValue:name=>name==='--browse-offset'?offset:'',height:`${element.getBoundingClientRect().height}px`,paddingBottom:element.classList.contains('alphabet-side-navigation')?`${safeBottom}px`:'0px'}),parseFloat,performance:{now:()=>0}});
  const flush=()=>{let count=0;while(frames.size){if(++count>100)throw new Error('Animation frame loop');const batch=[...frames];frames.clear();batch.forEach(([,fn])=>fn());}};
  const side=()=>document.querySelector('.alphabet-side-navigation'),buttons=()=>side()?.querySelectorAll('.alphabet-side-letter')||[];
  return {document,window,sections,search,clear,scope,view,pageHeader,backToTop,frames,observers,resizeObservers,scrolls,flush,side,visible:()=>buttons().filter(button=>!button.hidden).sort((a,b)=>Number(a.style.order)-Number(b.style.order)).map(button=>button.dataset.letter),
    button:letter=>buttons().find(button=>button.dataset.letter===letter),
    setOffset:value=>{offset=value;},scroll:top=>{window.scrollY=top;window.fire('scroll');flush();},
    setMobile:matches=>{mobile=matches;window.innerWidth=matches?390:1200;const match=window.matchMedia('(max-width: 700px)');match.matches=matches;match.fire('change',{matches});window.fire('resize');flush();},
    pointer:(type,extra={})=>document.fire(type,{pointerId:1,pointerType:'touch',isPrimary:true,...extra})};
}
const movies=()=>[{name:'Movies',titles:['Alpha','Another','Beta','Zulu']}];
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
test('removing the keyboard-selected letter preserves a reachable desktop tab stop',()=>{
  const f=fixture(movies());f.flush();f.button('A').focus();f.button('A').fire('keydown',{key:'ArrowDown'});assert.equal(f.document.activeElement,f.button('B'));
  f.sections[0].cards[2].hidden=true;f.search.fire('input');f.flush();
  assert.equal(f.side().querySelectorAll('.alphabet-side-letter').filter(button=>!button.hidden&&button.tabIndex===0).length,1);
});
test('reordering the letter nodes preserves an available keyboard selection if the browser drops move focus',()=>{
  const f=fixture(movies(),{moveLosesFocus:true});f.flush();f.button('A').focus();f.button('A').fire('keydown',{key:'ArrowDown'});const focused=f.button('B');
  f.sections[0].cards[3].hidden=true;f.search.fire('input');f.flush();assert.equal(f.document.activeElement,focused);assert.equal(focused.tabIndex,0);assert.equal(focused.focusOptions.preventScroll,true);
});
test('jump offsets use current sticky dimensions and reduced motion',()=>{
  const f=fixture(movies(),{reduced:false});f.flush();f.setOffset('200px');f.sections[0].querySelector('.section-header').rect.height=100;
  const expected=Math.max(0,f.sections[0].cards[2].docTop-200-100-8);f.button('B').fire('click');assert.equal(f.scrolls.at(-1).top,expected);assert.equal(f.scrolls.at(-1).behavior,'smooth');const reduced=fixture(movies());reduced.flush();reduced.button('Z').fire('click');assert.equal(reduced.scrolls.at(-1).behavior,'instant');
});
test('card removals refresh once while generated side nodes do not cause observer loops',()=>{
  const f=fixture(movies());f.flush();const observer=f.observers.find(item=>item.target===f.view);assert.ok(observer);observer.callback([{type:'childList',target:f.side(),addedNodes:[f.button('A')],removedNodes:[]}]);assert.equal(f.frames.size,0);
  const removed=f.sections[0].cards[3];removed.remove();observer.callback([{type:'childList',target:f.sections[0],addedNodes:[],removedNodes:[removed]}]);observer.callback([{type:'attributes',target:f.sections[0].cards[0]}]);assert.equal(f.frames.size,1);f.flush();assert.deepEqual(f.visible(),['A','B']);
});
test('untrusted names stay text and refresh works without MutationObserver',()=>{
  const f=fixture([{name:'<img onerror=alert(1)>',titles:['Alpha','Beta']}],{observerAvailable:false});f.flush();assert.match(f.button('A').getAttribute('aria-label'),/<img onerror=/);assert.equal(f.side().querySelectorAll('img').length,0);f.sections[0].cards[0].hidden=true;f.window.fire('pageshow');f.flush();assert.equal(f.side().hidden,true);
});
test('empty media pages do not add an unused side navigation',()=>{
  const f=fixture([]);f.flush();assert.equal(f.side(),null);assert.equal(f.observers.length,0);
});
test('the index depends on rendered section height and available initials, not title count',()=>{
  const f=fixture([...movies(),{name:'Shows',titles:['Charlie','Delta','Echo','Foxtrot'],height:420}]);f.flush();
  assert.equal(f.side().hidden,false);f.scroll(2200);assert.equal(f.side().hidden,true);
  f.sections[1].rect.height=1600;f.resizeObservers[0].callback();f.flush();assert.equal(f.side().hidden,false);
  f.window.visualViewport.height=1200;f.window.visualViewport.fire('resize');f.flush();assert.equal(f.side().hidden,true);
  f.window.visualViewport.height=600;f.window.visualViewport.fire('resize');f.flush();assert.equal(f.side().hidden,false);
  f.sections[1].cards.slice(1).forEach(card=>{card.hidden=true;});f.search.fire('input');f.flush();assert.equal(f.side().hidden,true);
});
test('filtering a large section down to a short grid hides its index and restoration brings it back',()=>{
  const f=fixture(movies());f.flush();assert.equal(f.side().hidden,false);
  f.sections[0].rect.height=450;f.search.fire('input');f.flush();assert.equal(f.side().hidden,true);
  f.sections[0].rect.height=1750;f.clear.fire('click');f.flush();assert.equal(f.side().hidden,false);
});
test('desktop rail sits beside the current grid even on a wide viewport',()=>{
  const f=fixture(movies());f.window.innerWidth=2560;f.sections[0].rect.left=40;f.sections[0].rect.width=1300;f.window.fire('resize');f.flush();
  assert.equal(f.side().style.left,'1348px');
  f.sections[0].rect.width=2400;f.window.fire('resize');f.flush();assert.equal(f.side().style.left,'2448px');
  f.setMobile(true);assert.equal(f.side().hidden,true);
});
test('a full desktop alphabet clears the visible app header and stays inside a short viewport',()=>{
  const titles=['2001',...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'];
  const f=fixture([{name:'Movies',titles,height:7500}],{scrollY:0,viewportHeight:600,headerHeight:180});f.flush();
  const index=f.side().querySelector('.alphabet-side-letters');
  const top=()=>parseFloat(f.side().style.top),height=()=>parseFloat(index.style.maxHeight);
  assert.equal(f.side().hidden,false);assert.equal(f.visible().length,27);
  assert.ok(top()>=f.pageHeader.getBoundingClientRect().bottom+8);
  assert.ok(top()+height()<=f.window.visualViewport.height-8);
  assert.ok(height()<27*24+8,'long indexes must scroll within their available height');
  f.button('#').focus();f.button('#').fire('keydown',{key:'End'});
  assert.equal(f.document.activeElement,f.button('Z'));assert.equal(f.button('Z').scrollOptions.block,'nearest');assert.equal(f.scrolls.length,0);
  f.pageHeader.rect.height=240;f.resizeObservers[0].callback();f.flush();
  assert.ok(f.resizeObservers[0].targets.includes(f.pageHeader));
  assert.ok(top()>=f.pageHeader.getBoundingClientRect().bottom+8);assert.ok(top()+height()<=592);
  f.search.focus();f.scroll(300);
  assert.equal(top(),128);assert.ok(top()+height()<=592);
});
test('desktop rail bounds refresh across library sections and visual viewport changes',()=>{
  const titles=['2001',...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'];
  const f=fixture([{name:'Movies',titles,height:7500},{name:'Shows',titles,height:7500,top:7800}],
    {scrollY:0,viewportHeight:600,viewportOffset:40,headerHeight:180,safeBottom:24});f.flush();
  const index=f.side().querySelector('.alphabet-side-letters');
  assert.ok(parseFloat(f.side().style.top)>=f.pageHeader.getBoundingClientRect().bottom+8);
  assert.ok(parseFloat(f.side().style.top)+parseFloat(index.style.maxHeight)<=608);
  f.scroll(8000);assert.match(index.getAttribute('aria-label'),/Shows/);assert.equal(f.visible().length,27);
  assert.equal(f.side().style.top,'168px');
  f.window.visualViewport.height=400;f.window.visualViewport.fire('resize');f.flush();
  assert.equal(f.side().style.top,'168px');assert.ok(parseFloat(f.side().style.top)+parseFloat(index.style.maxHeight)<=408);
  f.setMobile(true);assert.equal(f.side().hidden,true);
});
test('an index with no room below the header hides and restores focus until space returns',()=>{
  const f=fixture([{name:'Movies',titles:['Alpha','Beta'],height:7500}],{scrollY:0,viewportHeight:600,headerHeight:180});f.flush();
  f.button('B').focus();f.window.visualViewport.height=240;f.window.visualViewport.fire('resize');f.flush();
  assert.equal(f.side().hidden,true);assert.equal(f.document.activeElement,f.sections[0].querySelector('.section-header'));
  f.scroll(200);assert.equal(f.side().hidden,false);assert.ok(parseFloat(f.side().style.top)>=128);
});
test('a long index clears a visible back-to-top button when their horizontal bounds overlap',()=>{
  const f=fixture([{name:'Movies',titles:['2001',...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],height:7500}],{viewportHeight:600});f.flush();
  const index=f.side().querySelector('.alphabet-side-letters');
  f.backToTop.rect={top:530,left:780,width:46,height:46};f.backToTop.classList.add('visible');f.window.fire('scroll');f.flush();
  assert.ok(parseFloat(f.side().style.top)+parseFloat(index.style.maxHeight)<=522);
  f.backToTop.rect.left=700;f.window.fire('scroll');f.flush();
  assert.equal(parseFloat(f.side().style.top)+parseFloat(index.style.maxHeight),592);
  f.backToTop.rect.left=780;f.backToTop.classList.remove('visible');f.window.fire('scroll');f.flush();
  assert.equal(parseFloat(f.side().style.top)+parseFloat(index.style.maxHeight),592);
});
test('desktop letters remain neutral while scrolling and retain one predictable tab stop',()=>{
  const f=fixture([{name:'Movies',titles:['Alpha','Beta','Beta again','Zulu']}]);
  const cards=f.sections[0].cards;cards[1].docTop=cards[0].docTop;cards[2].docTop=600;
  f.window.KeepAlphabet.refresh();f.flush();f.scroll(500);
  assert.equal(f.button('A').getAttribute('aria-current'),null);assert.equal(f.button('B').getAttribute('aria-current'),null);
  assert.equal(f.button('A').tabIndex,0);assert.equal(f.button('B').tabIndex,-1);assert.equal(f.button('B').scrollOptions,undefined);
});
test('mobile has no scrubber, bubble, or visible letter index and ordinary pointer events remain untouched',()=>{
  const f=fixture(movies(),{mobile:true});f.flush();
  assert.equal(f.side().hidden,true);assert.equal(f.document.querySelector('[role="slider"]'),null);
  assert.equal(f.document.querySelector('.alphabet-scrub-track'),null);assert.equal(f.document.querySelector('.alphabet-scrub-bubble'),null);
  assert.equal(f.document.listeners.pointermove,undefined);assert.equal(f.document.listeners.pointerup,undefined);
  const event=f.pointer('pointerdown',{clientY:200});assert.equal(event.defaultPrevented,false);
  f.scroll(700);f.button('B').fire('click');f.search.fire('input');f.clear.fire('click');f.flush();
  assert.equal(f.side().hidden,true);assert.equal(f.scrolls.length,0);
  f.setMobile(false);assert.equal(f.side().hidden,false);assert.deepEqual(f.visible(),['A','B','Z']);
});
test('a focused desktop index hands focus to its section before becoming too short to show',()=>{
  for(const change of ['height','viewport','one-letter']){
    const f=fixture(movies());f.flush();f.button('B').focus();
    if(change==='height'){f.sections[0].rect.height=450;f.resizeObservers[0].callback();}
    else if(change==='viewport'){f.window.visualViewport.height=1200;f.window.visualViewport.fire('resize');}
    else{f.sections[0].cards.slice(2).forEach(card=>{card.hidden=true;});f.search.fire('input');}
    f.flush();const header=f.sections[0].querySelector('.section-header');
    assert.equal(f.side().hidden,true);assert.equal(f.document.activeElement,header);assert.equal(header.tabIndex,-1);
    assert.equal(header.focusOptions.preventScroll,true);assert.equal(f.scrolls.length,0);
  }
});
test('crossing into mobile restores keyboard focus even when CSS first drops it to body',()=>{
  for(const browserDropsFocus of [false,true]){
    const f=fixture(movies());f.flush();f.button('B').focus();
    if(browserDropsFocus)f.document.activeElement=f.document.body;
    f.setMobile(true);const header=f.sections[0].querySelector('.section-header');
    assert.equal(f.side().hidden,true);assert.equal(f.document.activeElement,header);assert.equal(header.focusOptions.preventScroll,true);
    f.setMobile(false);assert.equal(f.side().hidden,false);assert.equal(f.document.activeElement,header);assert.equal(f.scrolls.length,0);
  }
});
test('removing the focused index collection leaves focus on an available heading or search',()=>{
  const f=fixture([...movies(),{name:'Shows',titles:['Charlie','Delta']}]);f.flush();f.button('A').focus();
  f.sections[0].hidden=true;f.window.KeepAlphabet.refresh();f.flush();
  const header=f.sections[1].querySelector('.section-header');assert.equal(f.document.activeElement,header);assert.equal(header.focusOptions.preventScroll,true);
  const all=fixture(movies());all.flush();all.button('A').focus();all.sections[0].hidden=true;all.window.KeepAlphabet.refresh();all.flush();
  assert.equal(all.document.activeElement,all.search);assert.equal(all.search.focusOptions.preventScroll,true);assert.equal(all.scrolls.length,0);
});
test('hiding an unfocused desktop index does not steal focus from search',()=>{
  const f=fixture(movies());f.flush();f.search.focus();f.sections[0].rect.height=450;f.search.fire('input');f.flush();
  assert.equal(f.side().hidden,true);assert.equal(f.document.activeElement,f.search);
});
