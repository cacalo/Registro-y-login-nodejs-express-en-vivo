import bcryptjs from "bcryptjs";
import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";
import {enviarMailVerificacion} from "./../services/mail.service.js"

dotenv.config();

export const usuarios = [ {
  user: 'Calo',
  email: 'contacto@puntojson.com',
  password: '$2a$05$0viEwcPX3mZcB6BNkVZzcea8ouNS60mDlzxgxjwFgX7E/LrVr3PO.',
  verificado: false
}]


async function login(req,res){
  console.log(req.body);
  const user = req.body.user;
  const password = req.body.password;
  if(!user || !password){
    return res.status(400).send({status:"Error",message:"Los campos están incompletos"})
  }
  const usuarioAResvisar = usuarios.find(usuario => usuario.user === user && usuario.verificado);
  if(!usuarioAResvisar){
    return res.status(400).send({status:"Error",message:"Error durante login"})
  }
  const loginCorrecto = await bcryptjs.compare(password,usuarioAResvisar.password);
  if(!loginCorrecto){
    return res.status(400).send({status:"Error",message:"Error durante login"})
  }
  const token = jsonwebtoken.sign(
    {user:usuarioAResvisar.user},
    process.env.JWT_SECRET,
    {expiresIn:process.env.JWT_EXPIRATION});

    const cookieOption = {
      expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
      path: "/"
    }
    res.cookie("jwt",token,cookieOption);
    res.send({status:"ok",message:"Usuario loggeado",redirect:"/admin"});
}

async function register(req,res){
  const user = req.body.user;
  const password = req.body.password;
  const email = req.body.email;
  if(!user || !password || !email){
    return res.status(400).send({status:"Error",message:"Los campos están incompletos"})
  }
  const usuarioAResvisar = usuarios.find(usuario => usuario.user === user);
  if(usuarioAResvisar){
    return res.status(400).send({status:"Error",message:"Este usuario ya existe"})
  }
  const salt = await bcryptjs.genSalt(5);
  const hashPassword = await bcryptjs.hash(password,salt);

  //Enviar el mail de verificación al cliente
  const tokenVerificacion = jsonwebtoken.sign(
    {user:user},
    process.env.JWT_SECRET,
    {expiresIn:process.env.JWT_EXPIRATION});

  const mail = await enviarMailVerificacion(email,tokenVerificacion)
  console.log(mail)
  if(mail.accepted===0){
    return res(500).send({status:"error",message:"Error enviando mail de verificación"})
  }
  const nuevoUsuario ={
    user, email, password: hashPassword, verificado:false
  }
  usuarios.push(nuevoUsuario);
  console.log(usuarios);
  return res.status(201).send({status:"ok",message:`Usuario ${nuevoUsuario.user} agregado`,redirect:"/"})
}

function verificarCuenta(req,res){
  try{
    if(!req.params.token){
      return res.redirect("/")
    }
    const decodificada = jsonwebtoken.verify(req.params.token,process.env.JWT_SECRET);
    if(!decodificada || !decodificada.user){
      return res.redirect("/").send({status:"error",message:"Error en el token"});
    }
    const token = jsonwebtoken.sign(
      {user:decodificada.user},
      process.env.JWT_SECRET,
      {expiresIn:process.env.JWT_EXPIRATION});
  
      const cookieOption = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),
        path: "/"
      }

      const indexUsuarioAActualizar = usuarios.findIndex(usuario => usuario.user === decodificada.user);
      usuarios[indexUsuarioAActualizar].verificado = true;

      res.cookie("jwt",token,cookieOption);
      console.log("USUARIO VERIFICADO")
      res.redirect("/");
  } catch (err) {
    console.warn(err)
    res.status(500);
    res.redirect("/")
  }
}

export const methods = {
  login,
  register,
  verificarCuenta
}