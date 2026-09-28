const H={"content-type":"application/json; charset=utf-8","cache-control":"no-store"};
const json=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:H});
const fail=(x,s=400)=>json({error:x},s);
async function body(r){try{return await r.json()}catch{return {}}}
async function sha(t){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(t));let s="";for(const x of new Uint8Array(b))s+=String.fromCharCode(x);return btoa(s)}
async function user(env,r){const h=r.headers.get("authorization")||"";if(!h.startsWith("Bearer "))return null;const x=await sha(h.slice(7));return await env.DB.prepare("SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(x,Date.now()).first()}
async function audit(env,u,a,d=""){await env.DB.prepare("INSERT INTO audit_log(username,action,details,created_at) VALUES(?,?,?,?)").bind(u.username,a,String(d).slice(0,1500),Date.now()).run()}

function ghConfig(env){
  const owner=String(env.GITHUB_OWNER||'').trim();
  const repo=String(env.GITHUB_REPO||'').trim();
  const branch=String(env.GITHUB_BRANCH||'main').trim();
  const token=String(env.GITHUB_TOKEN||'').trim();
  if(!owner||owner.startsWith('REPLACE_')||!repo||repo.startsWith('REPLACE_'))throw new Error('חיבור GitHub לא הוגדר: GITHUB_OWNER/GITHUB_REPO');
  if(!token)throw new Error('חיבור GitHub לא הוגדר: חסר GITHUB_TOKEN כסוד של Worker');
  return {owner,repo,branch,token};
}
function b64utf8(t){
  const bytes=new TextEncoder().encode(String(t));let bin='';
  for(let i=0;i<bytes.length;i+=0x8000)bin+=String.fromCharCode(...bytes.subarray(i,i+0x8000));
  return btoa(bin);
}
function utf8b64(s){
  const bin=atob(String(s).replace(/\s/g,''));const bytes=new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++)bytes[i]=bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}
async function githubRequest(env,path,options={}){
  const g=ghConfig(env);
  const url='https://api.github.com/repos/'+encodeURIComponent(g.owner)+'/'+encodeURIComponent(g.repo)+'/contents/'+path.split('/').map(encodeURIComponent).join('/')+'?ref='+encodeURIComponent(g.branch);
  const r=await fetch(url,{...options,headers:{'Accept':'application/vnd.github+json','Authorization':'Bearer '+g.token,'X-GitHub-Api-Version':'2022-11-28','User-Agent':'Karnei-Shomron-Board',...(options.headers||{})}});
  const text=await r.text();let data={};try{data=JSON.parse(text)}catch{}
  if(!r.ok)throw new Error('GitHub '+r.status+': '+String(data.message||text).slice(0,300));
  return data;
}
async function githubReadFile(env,path){
  const data=await githubRequest(env,path);
  if(Array.isArray(data))throw new Error('הנתיב אינו קובץ: '+path);
  return {path,sha:String(data.sha||''),content:utf8b64(data.content||'')};
}
async function githubWriteFile(env,path,content,sha,message){
  const g=ghConfig(env);
  const url='https://api.github.com/repos/'+encodeURIComponent(g.owner)+'/'+encodeURIComponent(g.repo)+'/contents/'+path.split('/').map(encodeURIComponent).join('/');
  const r=await fetch(url,{method:'PUT',headers:{'Accept':'application/vnd.github+json','Authorization':'Bearer '+g.token,'X-GitHub-Api-Version':'2022-11-28','User-Agent':'Karnei-Shomron-Board','Content-Type':'application/json'},body:JSON.stringify({message,content:b64utf8(content),sha,branch:g.branch})});
  const text=await r.text();let data={};try{data=JSON.parse(text)}catch{}
  if(!r.ok)throw new Error('GitHub '+r.status+': '+String(data.message||text).slice(0,300));
  return data;
}
function extractJsonText(x){
  if(typeof x==='string')return x;
  if(x?.output_text)return x.output_text;
  const out=Array.isArray(x?.output)?x.output:[];let s='';
  for(const item of out){for(const c of (item?.content||[])){if(c?.type==='output_text')s+=String(c.text||'')}}
  return s;
}
async function makeCodePlan(env,msg){
  if(!env.OPENAI_API_KEY)throw new Error('חסר OPENAI_API_KEY כסוד של Worker');
  const paths=['public/index.html','src/index.js','wrangler.toml'];
  const files=[];
  for(const path of paths){try{const f=await githubReadFile(env,path);files.push({path,content:f.content.slice(0,120000)})}catch(e){}}
  if(!files.length)throw new Error('לא הצלחתי לקרוא קבצים מ-GitHub');
  const prompt=`אתה מתכנן תיקון קוד עבור אתר קהילתי בעברית.\nהמשימה של המשתמש: ${JSON.stringify(msg)}\n\nהקבצים העדכניים מה-repository:\n${files.map(f=>'--- '+f.path+' ---\\n'+f.content).join('\\n')}\n\nהחזר JSON בלבד, ללא Markdown, בצורה:\n{"path":"public/index.html","summary":"...","steps":["..."],"edits":[{"oldText":"טקסט קיים מדויק","newText":"הטקסט החדש"}]}\nכללים: בחר קובץ קיים בלבד; oldText חייב להופיע בדיוק בקובץ; אל תמציא קוד שאינו נחוץ; עדיף שינוי קטן וממוקד; עד 5 edits; אל תכלול סודות, Tokens או סיסמאות; אם אינך בטוח מה לשנות החזר edits ריק ו-summary שמסביר למה.\n`;
  const r=await fetch('https://api.openai.com/v1/responses',{method:'POST',headers:{'Authorization':'Bearer '+env.OPENAI_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({model:String(env.BOARD_CODE_MODEL||'gpt-5.6-sol'),input:prompt,max_output_tokens:5000})});
  const raw=await r.text();let data={};try{data=JSON.parse(raw)}catch{}
  if(!r.ok)throw new Error('OpenAI '+r.status+': '+String(data?.error?.message||raw).slice(0,300));
  let txt=extractJsonText(data).trim().replace(/^```(?:json)?/i,'').replace(/```$/,'').trim();
  let plan;try{plan=JSON.parse(txt)}catch{throw new Error('מנוע הקוד החזיר תשובה שאינה JSON תקין')}
  const path=String(plan.path||'').trim();
  if(!files.some(f=>f.path===path))throw new Error('המנוע בחר קובץ שאינו ברשימת הקבצים המורשים');
  const edits=Array.isArray(plan.edits)?plan.edits.slice(0,5).map(e=>({oldText:String(e.oldText||''),newText:String(e.newText||'')})).filter(e=>e.oldText&&e.oldText!==e.newText):[];
  if(!edits.length)throw new Error(String(plan.summary||'לא נמצא שינוי מדויק שאפשר לאשר בבטחה'));
  return {kind:'github_code_change',path,summary:String(plan.summary||'שינוי קוד'),steps:Array.isArray(plan.steps)?plan.steps.slice(0,8).map(String):[],edits};
}
async function executeCodeChange(env,u,p){
  const path=String(p.path||'').trim();
  if(!/^((public|src)\/[^\\/]+|wrangler\.toml)$/.test(path))throw new Error('הנתיב אינו מורשה לשינוי');
  const edits=Array.isArray(p.edits)?p.edits.slice(0,5):[];
  if(!edits.length)throw new Error('אין שינויים מאושרים לביצוע');
  const file=await githubReadFile(env,path);let content=file.content;
  for(const e of edits){
    const oldText=String(e.oldText||'');const newText=String(e.newText||'');
    if(!oldText)throw new Error('נמצא שינוי ללא oldText');
    const count=content.split(oldText).length-1;
    if(count!==1)throw new Error('השינוי לא בוצע: הקטע המאושר לא נמצא בדיוק פעם אחת בקובץ '+path);
    content=content.replace(oldText,newText);
  }
  const commitMessage='Board: approved code change';
  const result=await githubWriteFile(env,path,content,file.sha,commitMessage);
  await audit(env,u,'board_github_commit',JSON.stringify({path,commit:result?.commit?.sha||'',url:result?.commit?.html_url||''}));
  return {reply:`בוצע ✅ השינוי נשמר ב-GitHub בקובץ ${path}.`,action:'github_code_change',path,commitUrl:result?.commit?.html_url||null,commitSha:result?.commit?.sha||null};
}

async function board(req,env,u){
 if(!u||u.role!=="super_admin")return fail("בורד זמין רק למנהל הראשי",403);
 const b=await body(req);
 const msg=String(b.message||"").trim().slice(0,2000);
 const normalized=msg.replace(/\s+/g," ").trim();
 const approval=String(b.approvalPhrase||"").trim();
 const taskId=String(b.taskId||"").trim();
 const plan=(steps)=>({steps});
 const ACTIVATION="בורד בורדי";
 const EXECUTE="ברהב";

 // Stage 1: explicit activation. This does not execute anything.
 if(normalized===ACTIVATION){
   return json({stage:"ready",reply:"בורד הופעל. עכשיו כתוב את המשימה שתרצה לבצע. בשלב הזה אני רק אבנה תוכנית — לא אבצע שינוי.",needsApproval:false});
 }

 // Stage 3: explicit execution approval for the exact pending task.
 if(approval===EXECUTE || normalized===EXECUTE){
   if(!taskId)return json({stage:"waiting",reply:"אין משימה ממתינה לאישור. קודם כתוב בורד בורדי ואז את המשימה.",needsApproval:false},409);
   const pending=await env.DB.prepare("SELECT id,message,plan_json,status,expires_at FROM board_tasks WHERE id=? AND user_id=? AND status='pending' AND expires_at>? LIMIT 1").bind(taskId,u.id,Date.now()).first();
   if(!pending)return json({stage:"expired",reply:"האישור פג או שהמשימה כבר בוצעה. שלח את המשימה מחדש כדי לקבל תוכנית חדשה.",needsApproval:false},409);
   const p=JSON.parse(pending.plan_json||"{}");
   // Execution remains allowlisted. The confirmation phrase authorizes the stored plan,
   // not arbitrary code supplied together with the approval request.
   let result=null;
   if(p.kind==="add_category"){
     const name=String(p.name||"").trim().slice(0,40);
     const icon=String(p.icon||"🏷️").trim().slice(0,8);
     const existing=await env.DB.prepare("SELECT name,icon,color FROM categories WHERE name=?").bind(name).first();
     if(existing) result={reply:`הקטגוריה "${name}" כבר קיימת.`,action:"add_category",category:[existing.name,existing.icon,existing.color]};
     else{
       const palette=["#0ea5e9","#16a34a","#f59e0b","#8b5cf6","#ef4444","#0891b2"];
       const count=await env.DB.prepare("SELECT COUNT(*) c FROM categories").first();
       const color=palette[Number(count?.c||0)%palette.length];
       await env.DB.prepare("INSERT INTO categories(name,icon,color) VALUES(?,?,?)").bind(name,icon,color).run();
       result={reply:`בוצע ✅ הוספתי את קטגוריית "${name}".`,action:"add_category",category:[name,icon,color]};
     }
   }else if(p.kind==="set_announcement"){
     const announcement=String(p.text||"").trim().slice(0,300);
     await env.DB.prepare("INSERT INTO settings(key,value) VALUES('ann',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(announcement).run();
     result={reply:"בוצע ✅ הודעת דף הבית עודכנה.",action:"set_announcement",announcement};
   }else if(p.kind==="github_code_change"){
     result=await executeCodeChange(env,u,p);
   }else if(p.kind==="diagnose"){
     const [a,b,c,pendingCount]=await Promise.all([
       env.DB.prepare("SELECT COUNT(*) c FROM users").first(),
       env.DB.prepare("SELECT COUNT(*) c FROM posts").first(),
       env.DB.prepare("SELECT COUNT(*) c FROM categories").first(),
       env.DB.prepare("SELECT COUNT(*) c FROM posts WHERE status='pending'").first()
     ]);
     result={reply:`אבחון השרת הסתיים. משתמשים: ${a?.c||0}, מודעות: ${b?.c||0}, קטגוריות: ${c?.c||0}, מודעות ממתינות: ${pendingCount?.c||0}.`,action:"diagnose"};
   }else{
     await audit(env,u,"board_blocked_execution",pending.message);
     return json({stage:"blocked",reply:"המשימה הזו אינה מחוברת כרגע לכלי ביצוע מורשה. האישור לא מאפשר הרצת קוד חופשי או גישה לא מוגבלת לשרת.",needsApproval:false},422);
   }
   await env.DB.prepare("UPDATE board_tasks SET status='executed' WHERE id=?").bind(taskId).run();
   await audit(env,u,"board_execute",JSON.stringify({taskId,kind:p.kind}));
   return json({...result,stage:"executed",taskId,needsApproval:false});
 }

 // Stage 2: every non-control message is a plan request. It is never executed here.
 if(!b.activated && !taskId && normalized!==ACTIVATION){
   return json({stage:"locked",reply:"כדי להתחיל עם בורד כתוב בדיוק: בורד בורדי",needsApproval:false});
 }

 // Natural-language plan creation. Add capabilities here only when there is a real,
 // server-side allowlisted executor for them.
 let p=null;
 const addMatch=msg.match(/(?:תוסיף|הוסף|צור|פתח)\s+(?:קטגור(?:יה|יית)|קטגוריה)\s+["״']?([^"״'\n]+?)["״']?(?:\s+עם\s+(.+))?$/i);
 if(addMatch){
   const name=String(addMatch[1]||"").trim().slice(0,40);
   if(name)p={kind:"add_category",name,icon:String(addMatch[2]||"🏷️").trim().slice(0,8),steps:["בדיקת קיום הקטגוריה","הכנת השינוי","הצגת התוכנית","המתנה לאישור ברהב"]};
 }
 const annMatch=msg.match(/(?:שנה|עדכן|החלף)\s+(?:את\s+)?(?:הודעת\s+(?:דף\s*הבית|המערכת)|הודעה\s+ראשית)\s*(?:ל|:|-)\s*(.+)$/i);
 if(!p && annMatch)p={kind:"set_announcement",text:String(annMatch[1]||"").trim().slice(0,300),steps:["בדיקת הרשאת מנהל ראשי","הכנת עדכון הודעת המערכת","הצגת התוכנית","המתנה לאישור ברהב"]};
 if(!p && /קוד|באג|תקלה|תקן|תיקון|שנה|עדכן|כפתור|עיצוב|פונקציה|javascript|html|css|worker|github/i.test(msg)){
   try{p=await makeCodePlan(env,msg);p.steps=["קריאת הקוד העדכני מ-GitHub",...(p.steps||[]),"בדיקת התאמת השינויים", "המתנה לאישור ברהב"]}
   catch(e){p={kind:"unsupported",steps:["ניסיון לקרוא את קוד הפרויקט","בדיקת חיבור GitHub ומנוע הקוד","הצגת התקלה ללא שינוי בקוד"],error:String(e.message||e)}}
 }
 if(!p)p={kind:"unsupported",steps:["ניתוח הבקשה","בדיקת כלים מורשים זמינים","הצגת תוכנית בלבד","המתנה לאישור ברהב"]};

 const id=crypto.randomUUID();
 const expires=Date.now()+10*60*1000;
 await env.DB.prepare("INSERT INTO board_tasks(id,user_id,message,plan_json,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)")
   .bind(id,u.id,msg,JSON.stringify(p),"pending",Date.now(),expires).run();
 await audit(env,u,"board_plan",JSON.stringify({taskId:id,kind:p.kind}));
 return json({stage:"planned",taskId:id,reply:p.kind==="unsupported"?`קיבלתי. ${p.error||"אין כרגע כלי מורשה שמבצע את סוג המשימה הזו."}`:p.kind==="github_code_change"?`הכנתי תיקון קוד ל-${p.path}. עדיין לא בוצע שינוי.`:"קיבלתי את המשימה והכנתי תוכנית. עדיין לא בוצע שום שינוי.",action:"preview_change",needsApproval:true,plan:{steps:p.steps||[],file:p.path||null,summary:p.summary||null,changes:p.edits?.map(x=>({oldText:String(x.oldText||'').slice(0,180),newText:String(x.newText||'').slice(0,180)}))||[]},expiresAt:expires});
}

export default{async fetch(req,env){const u=await user(env,req),url=new URL(req.url);if(url.pathname==="/api/health")return json({status:"ok",platform:"cloudflare",twoAI:true});if(url.pathname==="/api/ai/board"&&req.method==="POST")return board(req,env,u);if(url.pathname==="/api/config"){const {results}=await env.DB.prepare("SELECT name,icon,color FROM categories ORDER BY rowid").all();const ann=await env.DB.prepare("SELECT value FROM settings WHERE key='ann'").first();return json({settings:{categories:results||[],ann:ann?.value||""}})}const r=await env.ASSETS.fetch(req);return r.status===404&&url.pathname==="/" ? env.ASSETS.fetch(new Request(new URL("/index.html",req.url))):r}}
