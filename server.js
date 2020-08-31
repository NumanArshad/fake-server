
const jsonserver = require("json-server")
const server = jsonserver.create()
const router = jsonserver.router("db.json")
const bodyparser = require("body-parser")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const fs = require("fs")

const data = JSON.parse(fs.readFileSync("./db.json", "utf8"))
const secretkey = "kjfnkfnenjbbh"
server.use(bodyparser.urlencoded({ extended: true }))
server.use(bodyparser.json())

const generateToken = (payload) => {
    return jwt.sign({ user: payload }, secretkey, { expiresIn: '2m' })
}

const verifyToken = (req, res, next) => {
    const { url } = req
    const protectedRoutes = url.includes("posts")
    /////////
    if (protectedRoutes) {
        const bearer = req.headers['authorization']
        try {
            const token = bearer.split(' ')[1]
            jwt.verify(token, secretkey, (error, authdata) => {
                if (error) {
                    console.log("token error" + error)
                    res.status(401).send({ token_error: "unAuthorized" })
                    return
                }
                //    res.status(200).send({ data: authdata })
                next()  // not to refersh if 
            })
        }
        catch{
            res.status(200).send({ token_error: "token not provided" })
        }
        return
    }
    //////////////////////////////
    next()
}


const isUserExist = (email) => {
    return data.users.find((data) => data.email === email)
}



server.post('/auth/login', async (req, res) => {
    const { email, password } = req.body

    const user = isUserExist(email)
    if (!user) { res.status(200).send({ login_status: "email not found" }); return }
    ////compare
    const result = await bcrypt.compare(password, user.password)
    if (result) {
        console.log(result)
        const token = generateToken(req.body)
        res.status(200).send({ token: token })
        return;
    }
    res.status(200).send({ login_status: "incorrcect password" })
})

server.post('/auth/register', async (req, res) => {
    const { email, password } = req.body
    const user = await isUserExist(email)
    if (user) { res.status(200).send({ signup_status: "email exist already" }); return }
    const hashpassword = await bcrypt.hash(password, 10)
    if (hashpassword) {
        await data.users.push({ id: data.users.length + 1, email: email, password: hashpassword })
        fs.writeFile("./db.json", JSON.stringify(data), (err) => {
            if (err) {
                console.log("file write errr" + err)
                // throw err
                res.status(200).send({ signup_status: "not_registered", error: err })
                return
            }
            const token = generateToken(req.body)
            res.status(200).send({ token: token })
        })
    }
})

server.use(verifyToken)
server.use('/api', router)
server.listen(4000, () => {
    console.log("json server running on port 4000")
})

// const auth=require("json-server-auth")
// server.db=router.db
// server.use(auth)
// const generateSalt = (password) => {
//     bcrypt.hash(password, 10, (err, hash) => {
//         if (err) {
//             return
//         }
//         console.log(hash)
//         return hash
//     })
// }
// server.post('/auth/verify', (req, res) => {
//     jwt.verify(req.body.token, secretkey, (err, data) => {
//         if (err) {
//             console.log("error in token sign")
//             res.status(400).send({ error: err })
//             return
//         }
//         res.status(200).send({ data: data.user })
//     })
// })

// console.log(faker.fake("{{name.lastName}}, {{name.firstName}} {{name.suffix}}"));
// console.log(faker.image.animals())

// server.get('/generateFake/:cnt?',(req,res)=>{
//     console.log("called"+req.params.cnt)
//     res.status(200).send({data:"fkwfbjbe"})
// })
//server.use(router)

// const rules=auth.rewriter({
//     users:600
//      // '///posts/:category': '/posts?category=:category',
//  })
//  server.use(rules)
//  server.db=router.db
//  server.use(auth)
// "start": "json-server --watch db.json --c port.json --routes routes.json",