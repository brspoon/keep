const {test}=require('node:test');
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../static/keep-toast.js'),'utf8');
function fixture({notice=null,error=null,pending=null}={}) {
 const classes=new Set(),text={},icon={};
 const toast={classList:{add:k=>classes.add(k),remove:k=>classes.delete(k),toggle:(k,on)=>on?classes.add(k):classes.delete(k)},querySelector:()=>icon};
 let storage=pending && JSON.stringify(pending);
 const context={window:{},document:{getElementById:id=>id==='toast'?toast:text,querySelector:s=>s.startsWith('#settings-error')?error:notice},location:{pathname:'/kept'},sessionStorage:{getItem:()=>storage,removeItem:()=>storage=null,setItem:(_,value)=>storage=value},setTimeout:()=>1,clearTimeout(){},Date};
 vm.runInNewContext(source,context);
 return {context,text,classes,stored:()=>storage};
}
test('confirmed server notices use the shared toast while keeping inline fallback hidden',()=>{
 const notice={textContent:'Settings saved.'};const f=fixture({notice});
 assert.equal(f.text.textContent,'Settings saved.');assert.equal(notice.hidden,true);assert.ok(f.classes.has('visible'));
});
test('errors never become successful save notifications',()=>{
 const f=fixture({notice:{textContent:'Saved'},error:{}});assert.equal(f.classes.has('visible'),false);
 f.context.window.showToast('Could not save',true);assert.equal(f.classes.has('error'),true);
});
test('refresh confirmation is consumed once and only on the matching recent page',()=>{
 const pending={message:'Keep extended by 30 days',path:'/kept',at:Date.now()};
 const f=fixture({pending});assert.equal(f.text.textContent,pending.message);assert.equal(f.stored(),null);
 assert.equal(fixture({pending:{...pending,path:'/'}}).classes.has('visible'),false);
 assert.equal(fixture({pending:{...pending,at:Date.now()-60000}}).classes.has('visible'),false);
 f.context.window.KeepToastAfterReload('Title kept indefinitely');assert.equal(JSON.parse(f.stored()).path,'/kept');
});
