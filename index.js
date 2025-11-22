import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bycrpt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth20";
import env from "dotenv";

env.config()

const db = new pg.Client({
  user: process.env.db_user,
  host: process.env.db_host,
  database: process.env.db_database,
  password: process.env.db_password,
  port: 5432,

})
db.connect();

const app = express();
const port = 3000;

app.use(session({
  secret: process.env.session_secret,
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

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"]
}))

app.get("/auth/google/secrets", passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}))

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/")
  })
})

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs")
  } else {
    res.redirect("/login")
  }
})

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("select secrets from users where email = $1", [req.user.email])
      const secret = result.rows[0].secrets;
      console.log("new secrets ->", secret);
      if (secret) {
        res.render("secrets.ejs", { secret: secret })
      } else {
        res.render("secrets.ejs", { secret: "no secrets" })
      }

    } catch (error) {
      console.log(error);
      return res.send("Error fetching your secret");

    }
  } else {
    res.redirect("/login")
  }
})

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
})
)

app.post("/register", async (req, res) => {
  const uEmail = req.body.username;
  const uPassword = req.body.password;

  try {
    const checkExistingUser = await db.query("select * from users where email = $1", [uEmail]);

    if (checkExistingUser.rows.length > 0) {
      res.send("email already exist please try different email")
    } else {
      bycrpt.hash(uPassword, 10, async (err, hash) => {
        if (err) {
          res.send(" register_ something went wrong!", err)
        }
        const result = await db.query("insert into users (email, password) values($1,$2) returning *", [uEmail, hash]);
        const user = result.rows[0]
        req.login(user, (err) => {
          console.log(err);
          res.redirect("/secrets")

        })
      })
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/submit", async (req, res) => {
  const newSecrets = req.body.secret;
  console.log(newSecrets);
  try {
    const result = await db.query("update users set secrets = $1 where email = $2", [newSecrets, req.user.email])
    res.redirect("/secrets")
  } catch (error) {
    console.log(error);

  }

})

passport.use(new Strategy(async function verify(username, password, cb) {
  try {
    const checkExistingUser = await db.query("select * from users where email = $1", [username]);

    if (checkExistingUser.rows.length > 0) {
      const user = checkExistingUser.rows[0]
      const dbPassword = user.password;

      bycrpt.compare(password, dbPassword, (err, valid) => {
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

    } else {
      return cb("user does not exist")
    }
  } catch (error) {
    console.log(error);

  }
}))

passport.use("google", new GoogleStrategy(
  {
    clientID: process.env.client_id,
    clientSecret: process.env.client_secret,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  }, async (accessToken, refreshToken, profile, cb) => {
    console.log("google email ->", profile.emails[0]);
    try {
      const result = await db.query("select * from users where email = $1", [profile.emails[0].value]);
      if (result.rows.length === 0) {
        const newUser = await db.query("insert into users (email, password) values($1, $2)", [profile.emails[0].value, "google"])
        cb(null, newUser.rows[0]);
      } else {
        cb(null, result.rows[0])
      }

    } catch (error) {
      return cb(error)
    }

  }
))

passport.serializeUser((user, cb) => {
  cb(null, user.id);
})

passport.deserializeUser(async (id, cb) => {
  const result = await db.query("select * from users where id = $1", [id]);
  const user = result.rows[0]
  console.log("deserial ->", user);

  cb(null, user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
