const H={"content-type":"application/json; charset=utf-8","cache-control":"no-store"};
const json=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:H});
const fail=(x,s=400)=>json({error:x},s);
async function body(r){try{return await r.json()}catch{return {}}}
async function sha(t){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(t));let s="";for(const x of new Uint8Array(b))s+=String.fromCharCode(x);return btoa(s)}
async function user(env,r){const h=r.headers.get("authorization")||"";if(!h.startsWith("Bearer "))return null;const x=await sha(h.slice(7));return await env.DB.prepare("SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?").bind(x,Date.now()).first()}
async function audit(env,u,a,d=""){await env.DB.prepare("INSERT INTO audit_log(username,action,details,created_at) VALUES(?,?,?,?)").bind(u.username,a,String(d).slice(0,1500),Date.now()).run()}
async function board(req,env,u){
 if(!u||u.role!=="super_admin")return fail("בורד זמין רק למנהל הראשי",403);
 const b=await body(req);
 const msg=String(b.message||"").trim().slice(0,2000);
 const normalized=msg.replace(/\s+/g," ").trim();
 const approval=String(b.approvalPhrase||"").trim();
 const taskId=String(b.taskId||"").trim();
 const ACTIVATION="בורד בורדי";
 const EXECUTE="ברהב";

 if(normalized===ACTIVATION){
   return json({stage:"ready",reply:"בורד הופעל. עכשיו כתוב את המשימה שתרצה לבצע. בשלב הזה אני רק אבנה תוכנית — לא אבצע שינוי.",needsApproval:false});
 }

 if(approval===EXECUTE || normalized===EXECUTE){
   if(!taskId)return json({stage:"waiting",reply:"אין משימה ממתינה לאישור. קודם כתוב בורד בורדי ואז את המשימה.",needsApproval:false},409);
   const pending=await env.DB.prepare("SELECT id,message,plan_json,status,expires_at FROM board_tasks WHERE id=? AND user_id=? AND status='pending' AND expires_at>? LIMIT 1").bind(taskId,u.id,Date.now()).first();
   if(!pending)return json({stage:"expired",reply:"האישור פג או שהמשימה כבר בוצעה. שלח את המשימה מחדש כדי לקבל תוכנית חדשה.",needsApproval:false},409);
   const p=JSON.parse(pending.plan_json||"{}");
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

 if(!b.activated && !taskId && normalized!==ACTIVATION){
   return json({stage:"locked",reply:"כדי להתחיל עם בורד כתוב בדיוק: בורד בורדי",needsApproval:false});
 }

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
