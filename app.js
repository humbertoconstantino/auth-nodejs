require ('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Configuração JSON Response
app.use(express.json())

// Models
const User = require('./models/User')
const { restart } = require('nodemon')

// Open Route - Public Route
app.get('/', (req,res) => {
    res.status(200).json({msg: "Bem Vindo a nossa API!"})
})

// Private Route
app.get('/user/:id', checkToken, async(req,res) =>{
    const id = req.params.id

    // Check if user exists
    const user = await User.findById(id, '-password')
    
    if(!user){
        return res.status(404).json({msg: "Usuário não encontrado"})
    }

    res.status(200).json({user})
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" "[1])

    if(!token){
        return res.status(401).json({msg: "Acesso negado!"})
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token,secret)

        next()
    } catch (error) {
        res.status(400).json({msg: "Token inválido"})
    }
}

// Registrar Usuário
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    // Validações
    if(!name){
        return res.status(422).json({msg: "O nome é obrigatório"})
    }

    if(!email){
        return res.status(422).json({msg: "O email é obrigatório"})
    }

    if(!password){
        return res.status(422).json({msg: "O password é obrigatório"})
    }

    if(!confirmpassword){
        return res.status(422).json({msg: "A confirmação de password é obrigatório"})
    }

    if(password !== confirmpassword){
        return res.status(422).json({msg: "Passwords diferentes"})
    }

    // Check se o user já existe
    const userExists = await User.findOne({email: email})

    if(userExists){
        return res.status(422).json({msg: "Email já utilizado"})
    }

    // Create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Create User
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
       
        await user.save()
        res.status(201).json({msg: "Usuário criado com sucesso!"})
        
    } catch (error) {
        console.log(error)

        res.status(500).json({msg: "Ocorreu um error no servidor, tente novamente!"})
    }

    }

)

// Login User
app.post('/auth/login', async (req, res) => {
    const {email, password} = req.body

    //Validação
    if (!email){
        return res.status(422).json({msg:"O email é obrigatório"})
    }
    if (!password){
        return res.status(422).json({msg:"O password é obrigatório"})
    }

    //Check if user exist
    const user = await User.findOne({email: email})

    if(!user){
        return res.status(404).json({msg: "Usuário não encontrado"})
    }

    //Check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(422).json({msg: "Senha inválida"})
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id
        },
        secret,
        )

        res.status(200).json({msg: "Autenticação realizada com sucesso!", token})
    } catch (error) {
        console.log(error)

        res.status(500).json({msg: "Ocorreu um error no servidor, tente novamente!"})
    }
})

// Credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@authjwtytb.mfnha.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then(() =>{
    app.listen(3000)
    console.log("Conectou ao banco!")
}).catch((err) => console.log(err))

