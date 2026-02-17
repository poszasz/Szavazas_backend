const express = require('express')
const cors = require('cors')
const cookieparser = require('cookie-parser')
const mysql = require('mysql2/promise')
const jwt = require('jsonwebtoken')
const req = require('express/lib/request')
const res = require('express/lib/response')
const emailValidator = require('doe-email-verifier')


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
    origin: '*',
    credentials: true
}))


//végpontok

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body
    // bemeneti adatok ellenőrzése
    if (!email || !felhasznalonev || !jelszo || !admin) {
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
        const regisztracioSQL = 'INSTERT INTO felhasznalok (email,felhasznalonev, jelszo, admin) VALUES (?,?,?,?)'
        const result = await db.query(regisztracioSQL, [email, felhasznalonev, hash, admin])

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
        let user ={}
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
                return res.status(402).json({ message: "Ezzel a felhasználónévvel címmel még nem regisztráltak" })
            }
        }
        const ok = bcrypt.compare(jelszo, ) //felh. vagy emailhez tartozo jelszo
        if (!ok) {
            return res.status(403).json({message:" rossz jelszot adtal meg"})
        }


        const token = jwt.sign(
            {id: user.id, email: user.email, felhasznalonev: user.felhasznalonev},
            JWT_SECRET,
            {expiresIn: JWT_EXPIRES_IN}
        )

        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({message: "sikeres belepes"})
    } catch (error) {
        console.log(error);
        return res.status(500).json({message: "Szerverhiba!"})
    }

})


//VÉDETT
app.post('/adataim', auth, async (req, res) => {
    
})


//szerver inditasa
app.listen(PORT, host, () => {
    console.log(`API fut: http://${host}:${PORT}/`)
})