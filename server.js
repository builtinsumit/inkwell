// ─────────────────────────────────────────────────────────────────────────────
//  Inkwell  –  Server.js
//  node server.js
// ─────────────────────────────────────────────────────────────────────────────
const express = require('express');
require("dotenv").config();
const { Pool } = require("pg");
const cors    = require('cors');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');

const app    = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ─── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'No token' });
    jwt.verify(token, SECRET, (err, payload) => {
        if (err) return res.status(403).json({ message: 'Token invalid or expired' });
        req.userId = payload.userId;
        next();
    });
}

// ─── DB ───────────────────────────────────────────────────────────────────────
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false
});

pool.connect()
.then(client => {
    console.log("✅ PostgreSQL Connected");
    client.release();
    setupTables();
})
.catch(err=>{
    console.error(err);
});

// ─── Table setup: create + migrate in one place ───────────────────────────────


// ─── POST /register ───────────────────────────────────────────────────────────
app.post('/register', async (req, res) => {

    const { name, phone, email, gender, username, password } = req.body;

    if (!name || !phone || !email || !gender || !username || !password) {
        return res.status(400).json({
            message: "All fields are required."
        });
    }

    try {

        const hash = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO users
            (name, phone, email, gender, username, password)
            VALUES ($1,$2,$3,$4,$5,$6)
            RETURNING id`,
            [name, phone, email, gender, username, hash]
        );

        res.status(201).json({
            message: "Account created!",
            userId: result.rows[0].id
        });

    }
    catch(err){

        if(err.code === "23505"){

            return res.status(409).json({
                message:"Email or Username already exists."
            });

        }

        console.error(err);

        res.status(500).json({
            message:"Database error."
        });

    }

});

// ─── POST /login ──────────────────────────────────────────────────────────────
app.post('/login', async (req,res)=>{

    const {username,password}=req.body;

    if(!username || !password){

        return res.status(400).json({
            message:"Username and password required."
        });

    }

    try{

        const result = await pool.query(

            "SELECT * FROM users WHERE username=$1",

            [username]

        );

        if(result.rows.length===0){

            return res.status(401).json({
                message:"Invalid username or password."
            });

        }

        const user=result.rows[0];

        const valid=await bcrypt.compare(password,user.password);

        if(!valid){

            return res.status(401).json({
                message:"Invalid username or password."
            });

        }

        const token=jwt.sign(

            {
                userId:user.id,
                username:user.username
            },

            SECRET,

            {
                expiresIn:"8h"
            }

        );

        res.json({

            message:"Login successful!",

            token,

            userId:user.id,

            username:user.username,

            name:user.name

        });

    }

    catch(err){

        console.error(err);

        res.status(500).json({
            message:"Database error."
        });

    }

});

// ─── POST /save-diary ─────────────────────────────────────────────────────────
// Body: { page_number: int, type: 'personal'|'public', content: string }
app.post("/save-diary", auth, async (req, res) => {

    let { page_number, type, content } = req.body;

    page_number = parseInt(page_number);

    if (!page_number || page_number < 1) {
        return res.status(400).json({
            message: "Invalid page number."
        });
    }

    if (!["personal", "public"].includes(type)) {
        return res.status(400).json({
            message: "Invalid diary type."
        });
    }

    content = content || "";

    try {

        await pool.query(

            `INSERT INTO diary_entries
            (user_id,page_number,type,content)

            VALUES($1,$2,$3,$4)

            ON CONFLICT(user_id,page_number,type)

            DO UPDATE

            SET content = EXCLUDED.content,
                updated_at = CURRENT_TIMESTAMP`,

            [req.userId,page_number,type,content]

        );

        res.json({ ok:true });

    }
    catch(err){

        console.error(err);

        res.status(500).json({

            message:"Save failed."

        });

    }

});

// ─── GET /get-diary/:type/:page ───────────────────────────────────────────────
app.get("/get-diary/:type/:page", auth, async (req,res)=>{

    const type=req.params.type;
    const page=parseInt(req.params.page);

    try{

        const result=await pool.query(

            `SELECT content,
                    updated_at

             FROM diary_entries

             WHERE user_id=$1
             AND page_number=$2
             AND type=$3`,

             [req.userId,page,type]

        );

        if(result.rows.length===0){

            return res.json({

                content:"",
                date:null

            });

        }

        res.json({

            content:result.rows[0].content,

            date:result.rows[0].updated_at

        });

    }

    catch(err){

        console.error(err);

        res.status(500).json({

            message:"Load failed."

        });

    }

});

// ─── GET /public-diary ────────────────────────────────────────────────────────
app.get("/public-diary", async(req,res)=>{

    try{

        const result=await pool.query(

            `SELECT

                d.page_number,
                d.content,
                d.updated_at,

                u.name,
                u.username

             FROM diary_entries d

             JOIN users u

             ON d.user_id=u.id

             WHERE d.type='public'

             AND d.content<>''

             ORDER BY d.updated_at DESC

             LIMIT 200`

        );

        res.json(result.rows);

    }

    catch(err){

        console.error(err);

        res.status(500).json({

            message:"Database error."

        });

    }

});
// ─── GET /my-stats ────────────────────────────────────────────────────────────
app.get("/my-stats",auth,async(req,res)=>{

    try{

        const result=await pool.query(

            `SELECT

            COUNT(*) AS pages,

            COALESCE(

            SUM(

            LENGTH(content)-LENGTH(REPLACE(content,' ',''))+1

            ),0) AS words,

            MIN(updated_at) AS first_date

            FROM diary_entries

            WHERE user_id=$1

            AND content<>''`,

            [req.userId]

        );

        const r=result.rows[0];

        const days=r.first_date

        ? Math.max(

            1,

            Math.round(

                (Date.now()-new Date(r.first_date))/86400000

            )

        )

        :0;

        res.json({

            pages:Number(r.pages),

            words:Number(r.words),

            days

        });

    }

    catch(err){

        console.error(err);

        res.status(500).json({

            message:"Database error."

        });

    }

});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT,()=>{
    console.log(`Server running on port ${PORT}`);
});
