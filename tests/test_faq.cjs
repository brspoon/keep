const {test} = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');

function fixture(fetcher) {
  const element = tag => ({tag,children:[],textContent:'',attributes:{role:'status','aria-live':'polite'},
    append(...nodes){this.children.push(...nodes);},
    replaceChildren(...nodes){this.children=nodes;},
    removeAttribute(name){delete this.attributes[name];}});
  const root=element('div');
  const document={getElementById:id=>id==='faq-criteria'?root:null,createElement:element,querySelector:()=>null};
  const window={location:{hash:''},addEventListener(){}};
  vm.runInNewContext(fs.readFileSync('static/keep-faq.js','utf8'),{document,window,fetch:fetcher});
  return root;
}

test('FAQ renders live per-library rules and watched thresholds as text',async()=>{
  const root=fixture(async()=>({ok:true,json:async()=>[
    {name:'Movies',kind:'movie',watched_percent:85,paths:['The movie was added about 2 years ago.','The movie has never been considered watched.']},
    {name:'Shows',kind:'tv',watched_percent:90,paths:['The newest episode was added about 1 year ago.']}
  ]}));
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(root.children.length,2);
  assert.equal(root.children[0].tag,'details');
  assert.equal(root.children[0].children[0].textContent,'Movies');
  assert.equal(root.children[0].children[1].textContent,'A movie is considered watched when someone watches at least 85% of it. A movie may appear in Leaving if any of these apply:');
  assert.equal(root.children[1].children[0].textContent,'Shows');
  assert.equal(root.children[1].children[1].textContent,'A show is considered watched when someone watches at least 90% of one of its episodes. A show may appear in Leaving if any of these apply:');
  assert.equal(root.children[0].children[2].children[0].textContent,'The movie was added about 2 years ago.');
  assert.equal(root.attributes.role,undefined);
});

test('FAQ offers a retry message when live rules are unavailable',async()=>{
  const root=fixture(async()=>({ok:false}));
  await new Promise(resolve=>setImmediate(resolve));
  assert.match(root.textContent,/could not be loaded/);
});

test('FAQ search filters answers, restores them, and reports no matches',async()=>{
  const listeners={};
  const search={value:'',addEventListener:(type,fn)=>listeners['search-'+type]=fn,focus(){this.focused=true;}};
  const clear={hidden:true,addEventListener:(type,fn)=>listeners['clear-'+type]=fn};
  const status={textContent:''};
  const empty={hidden:true};
  const question=textContent=>({textContent,hidden:false,open:false});
  const leavingQuestions=[question('Why do titles appear?'),question('The day badge shows time left')];
  const keptQuestions=[question('A Keep protects a title')];
  const section=(heading,questions)=>({hidden:false,
    querySelector:()=>({textContent:heading}),
    querySelectorAll:()=>questions});
  const sections=[section('Leaving',leavingQuestions),section('Kept',keptQuestions)];
  const root={textContent:'',querySelectorAll:()=>[]};
  const popular={hidden:false,querySelectorAll:()=>[]};
  const topics=[{dataset:{faqTopic:'leaving'},hidden:false},{dataset:{faqTopic:'keeps'},hidden:false}];
  const ids={'faq-criteria':root,'faq-search':search,'faq-search-clear':clear,
    'faq-search-status':status,'faq-search-empty':empty,'leaving':sections[0],'keeps':sections[1]};
  const document={getElementById:id=>ids[id]||null,
    querySelectorAll:selector=>selector==='.faq-section'?sections:topics,
    querySelector:()=>popular};
  const window={location:{hash:''},addEventListener(){}};
  vm.runInNewContext(fs.readFileSync('static/keep-faq.js','utf8'),{
    document,window,fetch:async()=>({ok:false})});
  await new Promise(resolve=>setImmediate(resolve));
  search.value='badge';
  listeners['search-input']();
  assert.equal(sections[0].hidden,false);
  assert.equal(sections[1].hidden,true);
  assert.equal(leavingQuestions[0].hidden,true);
  assert.equal(leavingQuestions[1].hidden,false);
  assert.equal(leavingQuestions[1].open,true);
  assert.equal(topics[1].hidden,true);
  assert.equal(popular.hidden,true);
  assert.equal(status.textContent,'1 question found');
  search.value='no such answer';
  listeners['search-input']();
  assert.equal(empty.hidden,false);
  search.value='kept';
  listeners['search-input']();
  assert.equal(sections[1].hidden,false);
  assert.equal(keptQuestions[0].hidden,false);
  listeners['clear-click']();
  assert.equal(search.value,'');
  assert.equal(search.focused,true);
  assert.equal(status.textContent,'');
  assert.equal(sections[0].hidden,false);
  assert.equal(sections[1].hidden,false);
  assert.equal(leavingQuestions[1].open,false);
  assert.equal(popular.hidden,false);
});
