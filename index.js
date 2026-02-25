const express = require('express')
const cors = require('cors')
const cookieparser = require('cookie-parser')
const mysql = require('mysql2/promise')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier')
const bcrypt = require('bcrypt')


// config
const PORT = 3000;
const HOST = 'localhost'
const JWT_SECRET = 'nagyon_nagyon_titkos_egyedi_jelszo'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth-token'


// cookie beállítás
const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',

    maxAge: 7 * 24 * 60 * 60 * 1000,

}

// adatbázis beáálítás

const db = mysql.createPool({
    host: 'localhost',
    port: '3306',
    user: 'root',
    password: '',
    database: 'szavazas'
})


//APP
const app = express();

app.use(express.json())
app.use(cookieparser())
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}))


//Middleware
function auth(req, res, next) {
    const token = req.cookies[COOKIE_NAME]
    if (!token) {
        return res.status(409).json({ message: "Nem vagy bejelentkezve" })
    } try {
        //tokenbol kinyerni a felhasznaloi adatokat
        req.user = jwt.verify(token, JWT_SECRET)
        next(); //haladhat tovabb a vegpontban
    } catch (error) {
        return res.status(410).json({ message: "Nem érvényes token" })
    }
}


//végpontok

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body
    // bemeneti adatok ellenőrzése
    if (!email || !felhasznalonev || !jelszo || !(admin===0 || admin===1)) {
        return res.status(400).json({ message: "Hiányos adat!" })
    }

    try {
        //valos emailcim
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: "Nem valós Emailt adtál meg!" })
        }

        // ellenőrizni a felhasználónevet és emailt, hogy egyedi-e
        const emailFelhasznalonevSQL = 'SELECT * FROM felhasznalok WHERE email = ? OR felhasznalonev = ?'
        const [exists] = await db.query(emailFelhasznalonevSQL, [email, felhasznalonev]);
        if (exists.length) {
            return res.status(402).json({ message: "Az email cím vagy felhasználónév már foglalt!" })
        }

        //regisztráció elvégzése
        const hash = await bcrypt.hash(jelszo, 10);
        const regisztracioSQL = 'INSERT  INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const [result] = await db.query(regisztracioSQL, [email, felhasznalonev, hash, admin])

        // válasz a felhasználónak
        return res.status(200).json({
            message: "Sikeres regisztráció",
            id: result.insertId
        })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: "Szerverhiba!" })
    }
})

app.post('/belepes', async (req, res) => {
    const { felhasznalonevVagyEmail, jelszo } = req.body;
    if (!felhasznalonevVagyEmail || !jelszo) {
        return res.status(400).json({ message: "Hiányos belépési adatok" })
    }
    try {
        //megadott fiokhoz milyen jelszo tartozik?
        const isValid = await emailValidator(felhasznalonevVagyEmail)
        let hashJelszo = "";
        let user = {}
        if (isValid) {
            //email + jelszót adott meg a belépéskor
            const sql = 'SELECT * FROM felhasznalok WHERE email=?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail])
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(401).json({ message: "Ezzel az email címmel még nem regisztráltak" })
            }
            //felhasználó + jelszót adott meg belépéskor

        } else {
            const sql = 'SELECT * FROM felhasznalok WHERE felhasznalonev=?'
            const [rows] = await db.query(sql, [felhasznalonevVagyEmail])
            if (rows.length) {
                user = rows[0];
                hashJelszo = user.jelszo;
            } else {
                return res.status(402).json({ message: "Ezzel a felhasználónévvel még nem regisztráltak" })
            }
        }
        const ok = bcrypt.compare(jelszo,) //felh. vagy emailhez tartozo jelszo
        if (!ok) {
            return res.status(403).json({ message: " rossz jelszot adtal meg" })
        }


        const token = jwt.sign(
            { id: user.id, email: user.email, felhasznalonev: user.felhasznalonev },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        )

        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({ message: "sikeres belépés" })
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "Szerverhiba!" })
    }

})






//VÉDETT 
app.post('/kijelentkezes', auth, async (req, res) => {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    res.status(200).json({ message: "Sikeres kijelentkezés" })
})

//VÉDETT
app.get('/adataim', auth, async (req, res) => {
    res.status(200).json(req.user)
})

//VÉDETT
app.put('/email', auth, async (req, res) => {
    const { ujEmail } = req.body
    if (!ujEmail) {
        return res.status(401).json({ message: "Az új email emgadása kötelező" })
    }
    const isValid = await emailValidator(ujEmail)
    if (!isValid) {
        return res.status(402).json({ message: "Az email formatuma nem jo halo!" })
    }
    try {
        sql1 = 'SELECT * FROM felhasznalok WHERE email = ?'
        const [result] = await db.query(sql1, [ujEmail])
        if (result.length) {
            return res.status(403).json({ message: "az email cim mar foglalt" })
        }
        const sql2 = 'UPDATE felhasznalok SET email = ? WHERE id = ?'
        await db.query(sql2, [ujEmail, req.user.id])
        return res.status(200).json({ message: "Sikeresen modosult az email" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "szerverhiba" })
    }
})

//VÉDETT
app.put('/felhasznalonev', auth, async (req, res) => {
    const { ujFelhasznalonev } = req.body
    //megnezem, hogy megadta e body-ban az uj felhasznalonevet a felhasznalo
    if (!ujFelhasznalonev) {
        return res.status(401).json({ message: "Az új felhasználónév emgadása kötelező" })
    }
    try {
        //megnezem, hogy a felhasznalonev szerepel e a rendszerben
        sql1 = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
        const [result] = await db.query(sql1, [ujFelhasznalonev])
        if (result.length) {
            return res.status(402).json({ message: "az email cim mar foglalt" })
        }
        //ha minden OK, modositom a felhasznalonevet
        const sql2 = 'UPDATE felhasznalok SET felhasznalonev = ? WHERE id = ?'
        await db.query(sql2, [ujFelhasznalonev, req.user.id])
        return res.status(200).json({ message: "Sikeresen modosult a felhasznalonev" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "szerverhiba" })
    }
})


app.put('/jelszo', auth, async (req, res) => {
    const { jelenlegiJelszo, ujJelszo } = req.body
    if (!jelenlegiJelszo || !ujJelszo) {
        return res.status(400).json({ message: "Hiányzó bemeneti adatok" })
    }
    try {
        //felhasználóhoz tartozo hashelt jelszot megkeresem
        const sql = 'SELECT * FROM felhasznalok WHERE id=?'
        const [rows] = await db.query(sql, [req.user.id])
        const user = rows[0];
        const hashJelszo = user.jelszo;
       // a jelenlegi jelszot osszevetjuk a hashelt jelszoval
       const ok = bcrypt.compare(jelenlegiJelszo,hashJelszo)
       if(!ok) {
        return res.status(401).json({message: "A régi jelszó nem helyes"})
       } 
       //új jelszó hashelése
       const hashUjJelszo = await bcrypt.hash(ujJelszo, 10);

       //új jelszó beállítás
       const sql2 = 'UPDATE felhasznalok SET jelszo = ? WHERE id = ?'
       await db.query(sql2, [hashUjJelszo,req.user.id])
       res.status(200).json({ message: "Új jelszó megadva" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "szerverhiba" })
    }
})


app.delete('/fiokom', auth, async (req, res) => {
    try {
        //toroljuk a felhasznalot
        const sql = 'DELETE FROM felhasznalok WHERE id =?'
        await db.query(sql, [req.user.id])
        //utolso lepes
        res.clearCookie(COOKIE_NAME, { path: '/' })
        res.status(200).json({ message: "Sikeres torles" })
    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "szerverhiba" })
    }
})


//szerver inditasa
app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})