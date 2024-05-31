import "dotenv/config"
import mongoose from "mongoose"
import express from "express"
import { User } from "./models/User.js"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
const app = express()

app.use(express.json())

app.get("/", (req, res) => {
  return res.json({ msg: "Bem-vindo a minha API!" })
})

function checkToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado!" })
  }

  try {
    const secret = process.env.SECRET

    jwt.verify(token, secret)

    next()
  } catch (error) {
    console.log(error)
    return res.status(400).json({ msg: "Token inválido!" })
  }
}
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id

  const user = await User.findById(id, "-password")

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" })
  }

  return res.json({ msg: "Bem-vindo a minha API!", user })
})

app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body

  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório!" })
  }

  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório!" })
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" })
  }

  if (!confirmpassword) {
    return res.status(422).json({ msg: "A confirmação da senha é obrigatório!" })
  }

  if (password !== confirmpassword) {
    return res.status(422).json({ msg: "As senhas não conferem!" })
  }

  const userExists = await User.findOne({ email: email })


  if (userExists) {
    return res.status(422).json({ msg: "Por favor, use outro email!" })
  }

  const salt = await bcrypt.genSalt(12)
  const hashPassword = await bcrypt.hash(password, salt)

  const user = new User({
    name,
    password: hashPassword,
    email
  })

  try {
    await user.save()

    res.status(201).json({ msg: "Usuário cadastrado com sucesso!" })

  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde!" })

  }
  return
})

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body

  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório!" })
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" })
  }

  const user = await User.findOne({ email: email })

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" })
  }

  const correctPassword = await bcrypt.compare(password, user.password)

  if (!correctPassword) {
    return res.status(422).json({ msg: "Senha inválida!" })
  }

  try {

    const secret = process.env.SECRET

    const token = jwt.sign({
      id: user._id
    }, secret, { expiresIn: "8h" })

    return res.status(200).json({ msg: "Autenticação realizada com sucesso!", token })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: "Aconteceu um erro no servidor, tente novamente mais tarde!" })
  }
})

const URL = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@schedule-bd.v1xqba3.mongodb.net/?retryWrites=true&w=majority&appName=schedule-bd`

mongoose
  .connect(URL)
  .then(() => {
    app.listen(3000)
    console.log("Conectado ao banco com sucesso!")
  })
  .catch((err) => console.log(err))