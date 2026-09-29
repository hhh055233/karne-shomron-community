const H={
  "content-type":"application/json; charset=utf-8",
  "cache-control":"no-store"
};

const json=(x,s=200)=>new Response(JSON.stringify(x),{
  status:s,
  headers:H
});

const fail=(x,s=400)=>json({error:x},s);

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

    return json({
      posts:results||[]
    });
  }

  if(req.method==="POST"){
    const b=await body(req);

    const id=String(
      b.id||crypto.randomUUID()
    ).slice(0,100);

    const item={
      id,
      cat:String(b.cat||"").slice(0,40),
      title:String(b.title||"").slice(0,120),
      desc:String(b.desc||"").slice(0,1500),
      age:String(b.age||"").slice(0,60),
      salary:String(b.salary||"").slice(0,80),
      location:String(b.location||"").slice(0,120),
      phone:String(b.phone||"").slice(0,40),
      author:String(b.author||"מבקר").slice(0,80),
      status:"pending",
      promo:0,
      date:String(
        b.date||new Date().toLocaleDateString("he-IL")
      ).slice(0,40),
      created_at:Date.now()
    };

    if(
      !item.cat||
      !item.title||
      !item.desc
    )
      return fail("חסרים פרטי מודעה",400);

    await env.DB.prepare(
      "INSERT OR REPLACE INTO posts(id,cat,title,desc,age,salary,location,phone,author,status,promo,date,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(
      item.id,
      item.cat,
      item.title,
      item.desc,
      item.age,
      item.salary,
      item.location,
      item.phone,
      item.author,
      item.status,
      item.promo,
      item.date,
      item.created_at
    ).run();

    return json({
      ok:true,
      post:item
    },201);
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

  const msg=String(
    b.message||""
  ).trim().slice(0,500);

  return json({
    reply:msg
      ?`קיבלתי את הבקשה. במצב זה המנהל הטכני יכול לבצע אבחון ופעולות מורשות בלבד. הבקשה שנבדקה: ${msg}`
      :"כתוב מה לבדוק."
  });
}

async function publicServiceAi(req,env){
  const b=await body(req);

  const msg=String(
    b.message||""
  ).trim().slice(0,500);

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
        (n,t)=>
          n+
          (
            String([
              p.cat,
              p.title,
              p.desc,
              p.location
            ].join(" "))
            .toLocaleLowerCase()
            .includes(t)
            ?1:0
          ),
        0
      )
    }))
    .filter(x=>x.score>0)
    .sort((a,b)=>b.score-a.score)
    .slice(0,3);

  return json({
    reply:
      matches.length
        ?`מצאתי ${matches.length} מודעות שיכולות להתאים לבקשה שלך.`
        :"לא מצאתי כרגע התאמה ברורה בלוח. נסה לכתוב מה אתה מחפש, אזור או סוג שירות.",

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

  const msg=String(
    b.message||""
  ).trim().slice(0,1000);

  return json({
    reply:msg
      ?`קיבלתי. אני יכול לעזור להפוך את זה למשימה מסודרת, להכין תשובה ללקוח או מפרט. הבקשה: ${msg}`
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
    preview:true,
    reply:
      "השרת זמין, אבל סוכן הפיתוח אינו מריץ קוד חופשי. פעולות שינוי חייבות לעבור דרך כלי מורשה."
  });
}


/* =========================================================
   BOARD
   ========================================================= */

async function board(req,env,u){

  const b=await body(req);

  const msg=String(
    b.message||""
  ).trim().slice(0,2000);

  const normalized=msg
    .replace(/\s+/g," ")
    .trim();

  const approval=String(
    b.approvalPhrase||""
  ).trim();

  const taskId=String(
    b.taskId||""
  ).trim();

  const plan=(steps)=>({steps});


  /* -----------------------------------------
     אישור פעולה
     מילת האישור היחידה: אישור
     ----------------------------------------- */

  if(
    normalized==="אישור"||
    approval==="אישור"
  ){

    if(!u){
      return json({
        stage:"login_required",
        reply:
          "הפעולה אושרה, אבל כדי לבצע שינוי באתר צריך להתחבר כמנהל ראשי.",
        needsApproval:false,
        requiresAdmin:true
      });
    }

    if(u.role!=="super_admin"){
      return json({
        stage:"permission_required",
        reply:
          "כדי לבצע שינוי באתר צריך הרשאת מנהל ראשי.",
        needsApproval:false,
        requiresAdmin:true
      });
    }

    if(!taskId){
      return json({
        stage:"waiting",
        reply:
          "אין כרגע משימה ממתינה לאישור. כתוב לבורד מה תרצה לבצע.",
        needsApproval:false
      },409);
    }

    const pending=await env.DB.prepare(
      "SELECT id,message,plan_json,status,expires_at FROM board_tasks WHERE id=? AND user_id=? AND status='pending' AND expires_at>? LIMIT 1"
    ).bind(
      taskId,
      u.id,
      Date.now()
    ).first();

    if(!pending){
      return json({
        stage:"expired",
        reply:
          "האישור פג או שהמשימה כבר בוצעה. שלח את המשימה מחדש כדי לקבל תוכנית חדשה.",
        needsApproval:false
      },409);
    }

    let p={};

    try{
      p=JSON.parse(
        pending.plan_json||"{}"
      );
    }catch{
      p={};
    }

    let result=null;


    /* הוספת קטגוריה */

    if(p.kind==="add_category"){

      const name=String(
        p.name||""
      ).trim().slice(0,40);

      const icon=String(
        p.icon||"🏷️"
      ).trim().slice(0,8);

      if(!name){
        return json({
          stage:"blocked",
          reply:"לא נמצא שם תקין לקטגוריה.",
          needsApproval:false
        },422);
      }

      const existing=await env.DB.prepare(
        "SELECT name,icon,color FROM categories WHERE name=?"
      ).bind(name).first();

      if(existing){

        result={
          reply:
            `הקטגוריה "${name}" כבר קיימת.`,
          action:"add_category",
          category:[
            existing.name,
            existing.icon,
            existing.color
          ]
        };

      }else{

        const palette=[
          "#0ea5e9",
          "#16a34a",
          "#f59e0b",
          "#8b5cf6",
          "#ef4444",
          "#0891b2"
        ];

        const count=await env.DB.prepare(
          "SELECT COUNT(*) c FROM categories"
        ).first();

        const color=
          palette[
            Number(count?.c||0)%palette.length
          ];

        await env.DB.prepare(
          "INSERT INTO categories(name,icon,color) VALUES(?,?,?)"
        ).bind(
          name,
          icon,
          color
        ).run();

        result={
          reply:
            `בוצע ✅ הוספתי את קטגוריית "${name}".`,
          action:"add_category",
          category:[
            name,
            icon,
            color
          ]
        };
      }


    /* שינוי הודעת מערכת */

    }else if(p.kind==="set_announcement"){

      const announcement=String(
        p.text||""
      ).trim().slice(0,300);

      await env.DB.prepare(
        "INSERT INTO settings(key,value) VALUES('ann',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).bind(
        announcement
      ).run();

      result={
        reply:
          "בוצע ✅ הודעת דף הבית עודכנה.",
        action:"set_announcement",
        announcement
      };


    /* אבחון */

    }else if(p.kind==="diagnose"){

      const [
        a,
        b2,
        c,
        pendingCount
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

      result={
        reply:
          `אבחון השרת הסתיים. `+
          `משתמשים: ${a?.c||0}, `+
          `מודעות: ${b2?.c||0}, `+
          `קטגוריות: ${c?.c||0}, `+
          `מודעות ממתינות: ${pendingCount?.c||0}.`,
        action:"diagnose"
      };


    /* כל פעולה אחרת */

    }else{

      await audit(
        env,
        u,
        "board_blocked_execution",
        pending.message
      );

      return json({
        stage:"blocked",
        reply:
          "המשימה הזו אינה מחוברת כרגע לכלי ביצוע מורשה. האישור אינו מאפשר הרצת קוד חופשי או גישה לא מוגבלת לשרת.",
        needsApproval:false
      },422);
    }


    await env.DB.prepare(
      "UPDATE board_tasks SET status='executed' WHERE id=?"
    ).bind(taskId).run();

    await audit(
      env,
      u,
      "board_execute",
      JSON.stringify({
        taskId,
        kind:p.kind
      })
    );

    return json({
      ...result,
      stage:"executed",
      taskId,
      needsApproval:false
    });
  }


  /* -----------------------------------------
     זיהוי משימות
     ----------------------------------------- */

  let p=null;


  /* הוספת קטגוריה */

  const addMatch=msg.match(
    /(?:תוסיף|הוסף|צור|פתח)\s+(?:קטגור(?:יה|יית)|קטגוריה)\s+["״']?([^"״'\n]+?)["״']?(?:\s+עם\s+(.+))?$/i
  );

  if(addMatch){

    const name=String(
      addMatch[1]||""
    ).trim().slice(0,40);

    if(name){

      p={
        kind:"add_category",
        name,
        icon:String(
          addMatch[2]||"🏷️"
        ).trim().slice(0,8),

        steps:[
          "בדיקת קיום הקטגוריה",
          "הכנת השינוי",
          "הצגת התוכנית",
          "המתנה לכתיבת אישור"
        ]
      };
    }
  }


  /* שינוי הודעת מערכת */

  const annMatch=msg.match(
    /(?:שנה|עדכן|החלף)\s+(?:את\s+)?(?:הודעת\s+(?:דף\s*הבית|המערכת)|הודעה\s+ראשית)\s*(?:ל|:|-)\s*(.+)$/i
  );

  if(!p&&annMatch){

    p={
      kind:"set_announcement",
      text:String(
        annMatch[1]||""
      ).trim().slice(0,300),

      steps:[
        "בדיקת הרשאת מנהל ראשי",
        "הכנת עדכון הודעת המערכת",
        "הצגת התוכנית",
        "המתנה לכתיבת אישור"
      ]
    };
  }


  /* אבחון */

  if(
    !p&&
    /בדוק|אבחון|באג|תקלה|סטטוס/.test(msg)
  ){

    p={
      kind:"diagnose",

      steps:[
        "בדיקת מסד הנתונים",
        "בדיקת משתמשים ומודעות",
        "בדיקת קטגוריות",
        "הצגת התוכנית",
        "המתנה לכתיבת אישור"
      ]
    };
  }


  /* משימה לא נתמכת */

  if(!p){

    p={
      kind:"unsupported",

      steps:[
        "ניתוח הבקשה",
        "בדיקת כלים מורשים זמינים",
        "הצגת תוכנית בלבד"
      ]
    };
  }


  /* -----------------------------------------
     אם אין משתמש מחובר
     ----------------------------------------- */

  if(!u){

    return json({
      stage:"planned",
      taskId:null,

      reply:
        p.kind==="unsupported"
          ?"קיבלתי. אני יכול להסביר ולתכנן את המשימה, אבל סוג הפעולה הזה עדיין לא מחובר לכלי ביצוע מורשה."
          :"קיבלתי את המשימה והכנתי תוכנית. לא בוצע שום שינוי באתר. כדי לבצע שינוי בפועל צריך להתחבר כמנהל ראשי.",

      action:"preview_change",

      needsApproval:false,

      requiresAdmin:
        p.kind!=="unsupported",

      plan:plan(p.steps)
    });
  }


  /* -----------------------------------------
     משתמש מחובר:
     שמירת משימה להמשך אישור
     ----------------------------------------- */

  const id=crypto.randomUUID();

  const expires=
    Date.now()+10*60*1000;

  await env.DB.prepare(
    "INSERT INTO board_tasks(id,user_id,message,plan_json,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?)"
  ).bind(
    id,
    u.id,
    msg,
    JSON.stringify(p),
    "pending",
    Date.now(),
    expires
  ).run();

  await audit(
    env,
    u,
    "board_plan",
    JSON.stringify({
      taskId:id,
      kind:p.kind
    })
  );


  return json({

    stage:"planned",

    taskId:id,

    reply:
      p.kind==="unsupported"
        ?"קיבלתי. הכנתי תוכנית, אבל אין עדיין כלי מורשה שמבצע את סוג המשימה הזו."
        :"קיבלתי את המשימה והכנתי תוכנית. עדיין לא בוצע שום שינוי. אם אתה רוצה לבצע את הפעולה, כתוב: אישור",

    action:"preview_change",

    needsApproval:
      p.kind!=="unsupported",

    plan:plan(p.steps),

    expiresAt:expires
  });
}


/* =========================================================
   SERVER
   ========================================================= */

export default{
  async fetch(req,env){

    const u=await user(env,req);
    const url=new URL(req.url);


    /* CORS */

    if(req.method==="OPTIONS"){

      return new Response(null,{
        status:204,

        headers:{
          "access-control-allow-origin":"*",
          "access-control-allow-methods":
            "GET,POST,PATCH,DELETE,OPTIONS",
          "access-control-allow-headers":
            "Content-Type,Authorization"
        }
      });
    }


    /* Health */

    if(url.pathname==="/api/health")
      return json({
        status:"ok",
        platform:"cloudflare",
        twoAI:true
      });


    /* Login */

    if(
      url.pathname==="/api/admin/login"&&
      req.method==="POST"
    )
      return adminLogin(req,env);


    /* Current user */

    if(
      url.pathname==="/api/auth/me"&&
      req.method==="GET"
    )
      return authMe(req,env);


    /* Admin users */

    if(
      url.pathname==="/api/admin/users"&&
      req.method==="GET"
    )
      return adminUsers(req,env,u);


    if(
      url.pathname.startsWith("/api/admin/users/")&&
      req.method==="PATCH"
    )
      return adminUserPatch(
        req,
        env,
        u,
        decodeURIComponent(
          url.pathname.slice(
            "/api/admin/users/".length
          )
        )
      );


    /* Posts */

    if(
      url.pathname==="/api/posts"||
      url.pathname.startsWith("/api/posts/")
    )
      return postsApi(
        req,
        env,
        u,
        url
      );


    /* Technical AI */

    if(
      url.pathname==="/api/ai/tech/diagnose"&&
      req.method==="POST"
    )
      return techDiagnose(
        req,
        env,
        u
      );


    if(
      url.pathname==="/api/ai/tech"&&
      req.method==="POST"
    )
      return techAsk(
        req,
        env,
        u
      );


    /* Developer AI */

    if(
      url.pathname==="/api/ai/developer"&&
      req.method==="POST"
    )
      return developerAi(
        req,
        env,
        u
      );


    /* Public service AI */

    if(
      url.pathname==="/api/ai/service"&&
      req.method==="POST"
    )
      return publicServiceAi(
        req,
        env
      );


    /* Owner AI */

    if(
      url.pathname==="/api/ai/owner"&&
      req.method==="POST"
    )
      return ownerAi(
        req,
        env,
        u
      );


    /* BOARD */

    if(
      url.pathname==="/api/ai/board"&&
      req.method==="POST"
    )
      return board(
        req,
        env,
        u
      );


    /* Config */

    if(
      url.pathname==="/api/config"&&
      req.method==="PATCH"
    ){

      if(
        !u||
        u.role!=="super_admin"
      )
        return fail(
          "אין הרשאה",
          403
        );

      const b=await body(req);

      const ann=String(
        b.ann||""
      ).trim().slice(0,300);

      const wa=String(
        b.wa||""
      ).replace(/[^\d+]/g,"").slice(0,20);

      await env.DB.prepare(
        "INSERT INTO settings(key,value) VALUES('ann',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).bind(
        ann
      ).run();

      if(wa){

        await env.DB.prepare(
          "INSERT INTO settings(key,value) VALUES('wa',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
        ).bind(
          wa
        ).run();
      }

      await audit(
        env,
        u,
        "settings_update",
        JSON.stringify({
          ann,
          wa:!!wa
        })
      );

      return json({
        ok:true
      });
    }


    /* Config GET */

    if(
      url.pathname==="/api/config"&&
      req.method==="GET"
    ){

      const {results}=await env.DB.prepare(
        "SELECT name,icon,color FROM categories ORDER BY rowid"
      ).all();

      const ann=await env.DB.prepare(
        "SELECT value FROM settings WHERE key='ann'"
      ).first();

      const wa=await env.DB.prepare(
        "SELECT value FROM settings WHERE key='wa'"
      ).first();

      return json({
        settings:{
          categories:results||[],
          ann:ann?.value||"",
          wa:wa?.value||""
        }
      });
    }


    /* Static files */

    const r=await env.ASSETS.fetch(req);

    return r.status===404&&url.pathname==="/"
      ?env.ASSETS.fetch(
        new Request(
          new URL(
            "/index.html",
            req.url
          )
        )
      )
      :r;
  }
}
