
const H={
  "content-type":"application/json; charset=utf-8",
  "cache-control":"no-store"
};

const json=(x,s=200)=>new Response(JSON.stringify(x),{
  status:s,
  headers:H
});

const fail=(x,s=400)=>json({error:x},s);
const ALLOWED_CATEGORIES = new Set(["חנויות","יד שנייה","למסירה","חוגים","אירועים","חדשות","דרושים"]);
const MANAGERS = ["manager","super_manager","super_admin"];


async function body(r){
  try{return await r.json()}
  catch{return {}}
}

async function sha(t){
  const b=await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(t)
  );
  let s="";
  for(const x of new Uint8Array(b))s+=String.fromCharCode(x);
  return btoa(s)
}

async function user(env,r){
  const h=r.headers.get("authorization")||"";
  if(!h.startsWith("Bearer "))return null;

  const x=await sha(h.slice(7));

  return await env.DB.prepare(
    "SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?"
  ).bind(x,Date.now()).first()
}

async function randomToken(){
  const b=new Uint8Array(32);
  crypto.getRandomValues(b);

  let s="";
  for(const x of b){
    s+=x.toString(16).padStart(2,"0");
  }

  return s;
}

async function adminLogin(req,env){
  const b=await body(req);
  const code=String(b.code||"").trim();

  if(!code||!env.ADMIN_CODE_HASH)
    return fail("כניסת מנהלים לא הוגדרה בשרת",503);

  const hash=await sha(code);

  if(hash!==String(env.ADMIN_CODE_HASH))
    return fail("קוד מנהל שגוי",401);

  let admin=await env.DB.prepare(
    "SELECT id,username,role FROM users WHERE role='super_admin' ORDER BY id LIMIT 1"
  ).first();

  if(!admin){
    await env.DB.prepare(
      "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)"
    ).bind(
      "admin",
      "ADMIN_CODE_AUTH",
      "super_admin"
    ).run();

    admin=await env.DB.prepare(
      "SELECT id,username,role FROM users WHERE role='super_admin' ORDER BY id LIMIT 1"
    ).first();
  }

  const token=await randomToken();
  const tokenHash=await sha(token);
  const expires=Date.now()+8*60*60*1000;

  await env.DB.prepare(
    "INSERT OR REPLACE INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)"
  ).bind(
    tokenHash,
    admin.id,
    expires,
    Date.now()
  ).run();

  await audit(env,admin,"admin_login","code_login");

  return json({
    token,
    user:{
      username:"מנהל",
      role:"super_admin"
    },
    expiresAt:expires
  });
}

async function audit(env,u,a,d=""){
  if(!u)return;

  await env.DB.prepare(
    "INSERT INTO audit_log(username,action,details,created_at) VALUES(?,?,?,?)"
  ).bind(
    u.username,
    a,
    String(d).slice(0,1500),
    Date.now()
  ).run();
}

async function requireMgr(env,req){
  const u=await user(env,req);

  if(
    !u||
    ![
      "manager",
      "super_manager",
      "super_admin"
    ].includes(u.role)
  )return null;

  return u;
}

async function authMe(req,env){
  const u=await user(env,req);

  if(!u)
    return fail("הסשן אינו תקף",401);

  return json({
    user:{
      id:u.id,
      username:u.username==="admin"?"מנהל":u.username,
      role:u.role
    }
  });
}

async function adminUsers(req,env,u){
  if(
    !u||
    ![
      "super_manager",
      "super_admin"
    ].includes(u.role)
  )return fail("אין הרשאה",403);

  const {results}=await env.DB.prepare(
    "SELECT id,username,role,created_at FROM users ORDER BY id"
  ).all();

  return json({
    users:results||[]
  });
}

async function adminUserPatch(req,env,u,target){
  if(
    !u||
    ![
      "super_manager",
      "super_admin"
    ].includes(u.role)
  )return fail("אין הרשאה",403);

  const b=await body(req);
  const nr=String(b.role||"").trim();

  if(
    ![
      "user",
      "manager",
      "super_manager",
      "super_admin"
    ].includes(nr)
  )return fail("תפקיד לא תקין",400);

  const targetUser=await env.DB.prepare(
    "SELECT id,username,role FROM users WHERE username=? LIMIT 1"
  ).bind(target).first();

  if(!targetUser)
    return fail("המשתמש לא נמצא",404);

  if(
    nr==="super_admin"&&
    u.role!=="super_admin"
  )
    return fail("רק מנהל ראשי יכול למנות מנהל ראשי",403);

  if(
    targetUser.role==="super_admin"&&
    u.role!=="super_admin"
  )
    return fail("רק מנהל ראשי יכול לשנות מנהל ראשי",403);

  if(
    targetUser.id===u.id&&
    nr!=="super_admin"
  )
    return fail(
      "אי אפשר להסיר את המנהל הראשי שמחובר כרגע",
      400
    );

  await env.DB.prepare(
    "UPDATE users SET role=? WHERE id=?"
  ).bind(
    nr,
    targetUser.id
  ).run();

  await audit(
    env,
    u,
    "role_change",
    JSON.stringify({
      target:targetUser.username,
      role:nr
    })
  );

  return json({
    ok:true,
    user:{
      id:targetUser.id,
      username:targetUser.username,
      role:nr
    }
  });
}

async function postsApi(req,env,u,url){

  if(req.method==="GET"){
    const admin=url.searchParams.get("admin")==="1";

    if(
      admin&&
      (
        !u||
        ![
          "manager",
          "super_manager",
          "super_admin"
        ].includes(u.role)
      )
    )
      return fail("אין הרשאה",403);

    const q=admin
      ?"SELECT * FROM posts ORDER BY created_at DESC"
      :"SELECT * FROM posts WHERE status='approved' ORDER BY created_at DESC";
    const {results}=await env.DB.prepare(q).all();
    const posts=(results||[]).map(p=>({...p,cat:p.cat==="יד2"?"יד שנייה":p.cat})).filter(p=>ALLOWED_CATEGORIES.has(p.cat));
    return json({posts});
  }

  if(req.method==="POST"){
    const b=await body(req);
    const cat=String(b.cat||"").trim();
    const title=String(b.title||"").trim().slice(0,120);
    const desc=String(b.desc||"").trim().slice(0,1500);
    if(!ALLOWED_CATEGORIES.has(cat)) return fail("קטגוריה לא מאושרת",400);
    if(!title||!desc) return fail("חסרים פרטי מודעה",400);
    if(cat==="אירועים"&&(!u||!MANAGERS.includes(u.role))) return fail("פרסום אירועים מתבצע דרך הנהלת האתר",403);
    if(cat==="חנויות"){
      const shopSetting=await env.DB.prepare("SELECT value FROM settings WHERE key='shop_free'").first();
      if(shopSetting?.value==="0") return fail("פרסום מודעות בחנויות אינו פתוח כרגע בחינם",402);
    }
    const id=String(b.id||crypto.randomUUID()).slice(0,100);
    const imageUrl=String(b.image_url||"").trim().slice(0,500);
    if(imageUrl && !imageUrl.startsWith("/media/")) return fail("כתובת תמונה לא תקינה",400);
    const item={
      id,cat,title,desc,
      age:String(b.age||"").slice(0,60),
      salary:String(b.salary||"").slice(0,80),
      location:String(b.location||"").slice(0,120),
      phone:String(b.phone||"").replace(/[^\d+]/g,"").slice(0,40),
      author:String(u?.username||"אורח").slice(0,80),
      image_url:imageUrl,
      status:cat==="דרושים"?"approved":"pending",
      promo:0,
      date:new Date().toLocaleDateString("he-IL"),
      created_at:Date.now()
    };
    await env.DB.prepare(
      "INSERT INTO posts(id,cat,title,desc,age,salary,location,phone,author,status,promo,date,created_at,image_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(item.id,item.cat,item.title,item.desc,item.age,item.salary,item.location,item.phone,item.author,item.status,item.promo,item.date,item.created_at,item.image_url).run();
    return json({ok:true,post:item},201);
  }

  const id=decodeURIComponent(
    url.pathname.split("/").pop()||""
  );

  if(
    !u||
    ![
      "manager",
      "super_manager",
      "super_admin"
    ].includes(u.role)
  )
    return fail("אין הרשאה",403);

  if(req.method==="DELETE"){
    await env.DB.prepare(
      "DELETE FROM posts WHERE id=?"
    ).bind(id).run();

    await audit(
      env,
      u,
      "post_delete",
      id
    );

    return json({ok:true});
  }

  if(req.method==="PATCH"){
    const b=await body(req);

    const current=await env.DB.prepare(
      "SELECT * FROM posts WHERE id=?"
    ).bind(id).first();

    if(!current)
      return fail("המודעה לא נמצאה",404);

    const status=
      b.status===undefined
        ?current.status
        :String(b.status).slice(0,20);

    const promo=
      b.promo===undefined
        ?current.promo
        :(b.promo?1:0);

    if(
      ![
        "pending",
        "approved"
      ].includes(status)
    )
      return fail("סטטוס לא תקין",400);

    await env.DB.prepare(
      "UPDATE posts SET status=?,promo=? WHERE id=?"
    ).bind(
      status,
      promo,
      id
    ).run();

    await audit(
      env,
      u,
      "post_update",
      JSON.stringify({
        id,
        status,
        promo
      })
    );

    return json({ok:true});
  }

  return fail(
    "שיטת בקשה לא נתמכת",
    405
  );
}

async function techDiagnose(req,env,u){
  if(
    !u||
    ![
      "super_manager",
      "super_admin"
    ].includes(u.role)
  )
    return fail("אין הרשאה",403);
  
  const [
    usersCount,
    postsCount,
    catsCount,
    pending
  ]=await Promise.all([
    env.DB.prepare(
      "SELECT COUNT(*) c FROM users"
    ).first(),

    env.DB.prepare(
      "SELECT COUNT(*) c FROM posts"
    ).first(),

    env.DB.prepare(
      "SELECT COUNT(*) c FROM categories"
    ).first(),

    env.DB.prepare(
      "SELECT COUNT(*) c FROM posts WHERE status='pending'"
    ).first()
  ]);

  return json({
    summary:
      `משתמשים: ${usersCount?.c||0}, `+
      `מודעות: ${postsCount?.c||0}, `+
      `קטגוריות: ${catsCount?.c||0}, `+
      `ממתינות: ${pending?.c||0}`
  });
}

async function techAsk(req,env,u){
  if(
    !u||
    ![
      "super_manager",
      "super_admin"
    ].includes(u.role)
  )
    return fail("אין הרשאה",403);

  const b=await body(req);
  const msg=String(b.message||"").trim().slice(0,500);

  return json({
    reply:msg
      ?`קיבלתי את הבקשה. כרגע אפשר לבצע אבחון ופעולות מורשות בלבד. הבקשה שנבדקה: ${msg}`
      :"כתוב מה לבדוק."
  });
}

async function publicServiceAi(req,env){
  const b=await body(req);
  const msg=String(b.message||"").trim().slice(0,500);

  const {results}=await env.DB.prepare(
    "SELECT id,cat,title,desc,location,phone FROM posts WHERE status='approved' ORDER BY created_at DESC LIMIT 35"
  ).all();

  const terms=msg
    .toLocaleLowerCase()
    .split(/\s+/)
    .filter(x=>x.length>2);

  const matches=(results||[])
    .map(p=>({
      p,
      score:terms.reduce(
        (n,t)=>n+(
          String([
            p.cat,p.title,p.desc,p.location
          ].join(" "))
          .toLocaleLowerCase()
          .includes(t)?1:0
        ),0
      )
    }))
    .filter(x=>x.score>0)
    .sort((a,b)=>b.score-a.score)
    .slice(0,3);

  return json({
    reply:matches.length
      ?`מצאתי ${matches.length} מודעות שיכולות להתאים לבקשה שלך.`
      :"לא מצאתי כרגע התאמה ברורה בלוח. נסה לכתוב מה אתה מחפש או באיזה אזור.",
    quick:matches.map(x=>x.p.title)
  });
}

async function ownerAi(req,env,u){
  if(
    !u||
    ![
      "manager",
      "super_manager",
      "super_admin"
    ].includes(u.role)
  )
    return fail("אין הרשאה",403);

  const b=await body(req);
  const msg=String(b.message||"").trim().slice(0,1000);

  return json({
    reply:msg
      ?`קיבלתי. אפשר להפוך את הבקשה למשימה מסודרת או למפרט. הבקשה: ${msg}`
      :"כתוב לי מה אתה צריך.",
    quick:[
      "תכין משימה",
      "תכין מפרט ללקוח"
    ]
  });
}

async function developerAi(req,env,u){
  if(
    !u||
    ![
      "super_manager",
      "super_admin"
    ].includes(u.role)
  )
    return fail("אין הרשאה",403);

  return json({
    action:"diagnose",
    reply:"כלי המפתח זמין לאבחון בסיסי. עדיין לא בוצע שינוי בקוד."
  });
}

async function board(req,env,u){
  const b=await body(req);
  const msg=String(b.message||"").trim().slice(0,1000);

  if(!msg)
    return json({
      stage:"chat",
      reply:"שלום! אני בורד. במה אוכל לעזור?",
      needsApproval:false
    });

  // אישור מבצע רק משימה שממתינה, של אותו מנהל.
  if(msg==="אישור"){
    if(!u||u.role!=="super_admin")
      return fail("רק מנהל ראשי יכול לאשר ביצוע",403);

    const pending=await env.DB.prepare(
      "SELECT id,message,plan_json FROM board_tasks WHERE user_id=? AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 1"
    ).bind(u.id,Date.now()).first();

    if(!pending)
      return json({
        stage:"chat",
        reply:"אין משימה שממתינה לאישור.",
        needsApproval:false
      });

    const p=JSON.parse(pending.plan_json||"{}");
    let result;

    if(p.kind==="add_category"){
      const name=String(p.name||"").trim().slice(0,40);

      if(!name||!ALLOWED_CATEGORIES.has(name)){
        return json({
          stage:"blocked",
          reply:"אפשר להוסיף רק את הקטגוריות הקבועות של האתר.",
          needsApproval:false
        },422);
      }

      const existing=await env.DB.prepare(
        "SELECT name,icon,color FROM categories WHERE name=?"
      ).bind(name).first();

      if(existing){
        result={
          reply:"הקטגוריה כבר קיימת.",
          action:"add_category"
        };
      }else{
        const palette=[
          "#0ea5e9","#16a34a","#f59e0b",
          "#8b5cf6","#ef4444","#0891b2"
        ];

        const count=await env.DB.prepare(
          "SELECT COUNT(*) c FROM categories"
        ).first();

        const color=palette[
          Number(count?.c||0)%palette.length
        ];

        await env.DB.prepare(
          "INSERT INTO categories(name,icon,color) VALUES(?,?,?)"
        ).bind(name,String(p.icon||"🏷️"),color).run();

        result={
          reply:`הקטגוריה "${name}" נוספה.`,
          action:"add_category"
        };
      }
    }else if(p.kind==="set_announcement"){
      const announcement=String(p.text||"").trim().slice(0,300);

      await env.DB.prepare(
        "INSERT INTO settings(key,value) VALUES('ann',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).bind(announcement).run();

      result={
        reply:"הודעת דף הבית עודכנה.",
        action:"set_announcement"
      };
    }else if(p.kind==="diagnose"){
      const posts=await env.DB.prepare(
        "SELECT COUNT(*) c FROM posts"
      ).first();

      result={
        reply:`האבחון הסתיים. מספר המודעות במסד הנתונים: ${posts?.c||0}.`,
        action:"diagnose"
      };
    }else{
      return json({
        stage:"blocked",
        reply:"סוג המשימה הזה אינו נתמך לביצוע אוטומטי.",
        needsApproval:false
      },422);
    }

    await env.DB.prepare(
      "UPDATE board_tasks SET status='executed' WHERE id=?"
    ).bind(pending.id).run();

    await audit(env,u,"board_execute",pending.id);

    return json({
      ...result,
      stage:"executed",
      taskId:pending.id,
      needsApproval:false
    });
  }

  let p=null;

  const addMatch=msg.match(
    /(?:תוסיף|הוסף|צור|פתח)\s+(?:קטגור(?:יה|יית)|קטגוריה)\s+["״']?([^"״'\n]+?)["״']?(?:\s+עם\s+(.+))?$/i
  );

  if(addMatch){
    const name=String(addMatch[1]||"").trim().slice(0,40);

    if(name){
      p={
        kind:"add_category",
        name,
        icon:String(addMatch[2]||"🏷️").trim().slice(0,8),
        steps:[
          "בדיקת הקטגוריה",
          "הצגת תוכנית",
          "המתנה לאישור מנהל ראשי"
        ]
      };
    }
  }

  const annMatch=msg.match(
    /(?:שנה|עדכן|החלף)\s+(?:את\s+)?(?:הודעת\s+(?:דף\s*הבית|המערכת)|הודעה\s+ראשית)\s*(?:ל|:|-)\s*(.+)$/i
  );

  if(!p&&annMatch){
    p={
      kind:"set_announcement",
      text:String(annMatch[1]||"").trim().slice(0,300),
      steps:[
        "הכנת הודעת דף הבית",
        "הצגת תוכנית",
        "המתנה לאישור מנהל ראשי"
      ]
    };
  }

  if(!p&&/בדוק|אבחון|באג|תקלה|סטטוס/.test(msg)){
    p={
      kind:"diagnose",
      steps:[
        "בדיקת נתוני האתר",
        "הצגת תוצאות האבחון"
      ]
    };
  }

  if(!p){
    return json({
      stage:"chat",
      reply:`קיבלתי את הבקשה שלך:\n\n"${msg}"\n\nאפשר להמשיך לתכנן את המשימה. לא בוצע שינוי באתר.`,
      needsApproval:false,
      action:"chat"
    });
  }

  if(!u){
    return json({
      stage:"planned",
      taskId:null,
      reply:"הכנתי תוכנית בלבד. כדי לבצע שינוי בפועל צריך להתחבר כמנהל ראשי.",
      action:"preview_change",
      needsApproval:false,
      requiresAdmin:true,
      plan:{steps:p.steps}
    });
  }

  if(u.role!=="super_admin")
    return fail("רק מנהל ראשי יכול לתכנן ולאשר שינויים",403);

  const id=crypto.randomUUID();
  const expires=Date.now()+10*60*1000;

  await env.DB.prepare(
    "INSERT INTO board_tasks(id,user_id,message,plan_json,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)"
  ).bind(
    id,u.id,msg,JSON.stringify(p),"pending",Date.now(),expires
  ).run();

  await audit(env,u,"board_plan",id);

  return json({
    stage:"planned",
    taskId:id,
    reply:"הכנתי תוכנית. עדיין לא בוצע שינוי. כדי לאשר, כתוב: אישור",
    action:"preview_change",
    needsApproval:true,
    plan:{steps:p.steps},
    expiresAt:expires
  });
}

async function health(env){
  const checks={database:false,assets:false};

  try{
    await env.DB.prepare("SELECT 1 AS ok").first();
    checks.database=true;
  }catch{}

  checks.assets=!!env.ASSETS;

  return json({
    ok:checks.database,
    service:"karnei-shomron",
    checks
  },checks.database?200:503);
}

export default {
  async fetch(req,env){
    const url=new URL(req.url);
    const path=url.pathname.replace(/\/+$/,"")||"/";
    const method=req.method.toUpperCase();

    if(method==="OPTIONS"){
      return new Response(null,{
        status:204,
        headers:{
          ...H,
          "access-control-allow-origin":url.origin,
          "access-control-allow-methods":"GET,POST,PATCH,DELETE,OPTIONS",
          "access-control-allow-headers":"Content-Type,Authorization",
          "access-control-max-age":"86400"
        }
      });
    }

    try{
      if(path==="/api/health"&&method==="GET"){
        return await health(env);
      }

      if(path==="/api/admin/login"&&method==="POST"){
        return await adminLogin(req,env);
      }

      if(path==="/api/auth/me"&&method==="GET"){
        return await authMe(req,env);
      }

      const u=await user(env,req);

      if(path==="/api/admin/users"&&method==="GET"){
        return await adminUsers(req,env,u);
      }

      const userMatch=path.match(/^\/api\/admin\/users\/([^/]+)$/);

      if(userMatch&&method==="PATCH"){
        return await adminUserPatch(
          req,env,u,decodeURIComponent(userMatch[1])
        );
      }

      if(path==="/api/posts"){
        return await postsApi(req,env,u,url);
      }

      if(path.startsWith("/api/posts/")){
        return await postsApi(req,env,u,url);
      }

      if(path==="/api/ai/tech/diagnose"&&method==="POST"){
        return await techDiagnose(req,env,u);
      }

      if(path==="/api/ai/tech"&&method==="POST"){
        return await techAsk(req,env,u);
      }

      if(path==="/api/ai/developer"&&method==="POST"){
        return await developerAi(req,env,u);
      }

      if(path==="/api/ai/service"&&method==="POST"){
        return await publicServiceAi(req,env);
      }

      if(path==="/api/ai/owner"&&method==="POST"){
        return await ownerAi(req,env,u);
      }

      if(
        (path==="/api/ai/board"||path==="/api/board/message")&&
        method==="POST"
      ){
        return await board(req,env,u);
      }

      if(path==="/api/board/tasks"&&method==="GET"){
        if(!u||u.role!=="super_admin")
          return fail("אין הרשאה",403);

        const {results}=await env.DB.prepare(
          "SELECT id,message,status,created_at,expires_at FROM board_tasks WHERE user_id=? ORDER BY created_at DESC LIMIT 50"
        ).bind(u.id).all();

        return json({tasks:results||[]});
      }

      if(path==="/api/config"&&method==="GET"){
        const rows=await env.DB.prepare(
          "SELECT key,value FROM settings"
        ).all();

        const config={};
        for(const r of rows.results||[]){
          config[r.key]=r.value;
        }

        return json({config});
      }

      if(path==="/api/config"&&method==="PATCH"){
        if(!u||!MANAGERS.includes(u.role))
          return fail("אין הרשאה",403);

        const b=await body(req);

        if(typeof b.shop_free==="boolean"){
          await env.DB.prepare(
            "INSERT INTO settings(key,value) VALUES('shop_free',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
          ).bind(b.shop_free?"1":"0").run();
        }

        await audit(env,u,"config_update","site settings");

        return json({ok:true});
      }

      if(path.startsWith("/api/")){
        return fail("נתיב API לא נמצא",404);
      }

      if(env.ASSETS){
        const assetUrl=new URL(req.url);

        if(path==="/"){
          assetUrl.pathname="/index.html";
        }

        return env.ASSETS.fetch(
          new Request(assetUrl,req)
        );
      }

      return fail("האתר לא הוגדר",503);

    }catch(e){
      console.error("Worker error:",e);

      return json({
        error:"שגיאה פנימית בשרת",
        path
      },500);
    }
  }
};
