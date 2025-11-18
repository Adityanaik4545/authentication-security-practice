import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bycrpt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "Aditya@123",
  port: 5432,

})
db.connect();

const app = express();
const port = 3000;

app.use(session({
  secret: "Topsecret",
  saveUninitialized: false,
  resave: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}))

app.use(passport.initialize())
app.use(passport.session())

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  
  if (req.isAuthenticated()) {
  res.render("secrets.ejs");
    
  } else {
    res.redirect("/login");
  }
});

app.post("/login", passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login"
}) 
)

app.post("/register", async (req, res) => {
  const uEmail = req.body.username;
  const uPassword = req.body.password;

try {
    const checkExistingUser = await db.query("select * from users where email = $1", [uEmail]);
    
    if (checkExistingUser.rows.length > 0 ) {
      res.send("email already exist please try different email")
    } else{
      bycrpt.hash(uPassword,10, async(err, hash)=>{
        if (err) {
          res.send(" register_ something went wrong!", err)
        }
        await db.query("insert into users (email, password) values($1,$2)", [uEmail, hash]);
        res.render("secrets.ejs");
      })
    }
} catch (error) {
  console.log(error);
}
});

passport.use(new Strategy(async function verify(username, password, cb) {
    try {
        const checkExistingUser = await db.query("select * from users where email = $1", [username]);
    
    if (checkExistingUser.rows.length > 0 ) {
      const user = checkExistingUser.rows[0]
      const dbPassword = user.password;

      bycrpt.compare(password, dbPassword, (err, valid)=>{
        if (err) {
          console.log("error comparing password!", err);
          return cb(err)
        } else {
          if (valid) {
            return cb(null, user);
          } else {
            return cb(null, false)
          }
        }
      })
      
    } else{
      return cb("user does not exist")
    }
  } catch (error) {
    console.log(error);
    
  }
}))

passport.serializeUser((user, cb)=>{
  cb(null, user.id);
})

passport.deserializeUser(async(id, cb)=>{
   const result = await db.query("select * from users where id = $1", [id]);
    const user = result.rows[0]
    console.log("deserial ->",user);
    
  cb(null, user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
