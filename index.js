import express from "express";
import bodyParser from "body-parser";
import pg from "pg";

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

app.post("/register", async (req, res) => {
  const uEmail = req.body.username;
  const uPassword = req.body.password;

try {
    const checkExistingUser = await db.query("select * from users where email = $1", [uEmail]);
    
    if (checkExistingUser.rows.length > 0 ) {
      res.send("email already exist please try different email")
    } else{
      await db.query("insert into users (email, password) values($1,$2)", [uEmail, uPassword]);
      res.render("secrets.ejs");
    }
} catch (error) {
  console.log(error);
}
});

app.post("/login", async (req, res) => {
    const uEmail = req.body.username;
  const uPassword = req.body.password;
  try {
        const checkExistingUser = await db.query("select * from users where email = $1", [uEmail]);
    
    if (checkExistingUser.rows.length > 0 ) {
      const result = await db.query("select password from users where email = $1", [uEmail])
      const dbPassword = result.rows[0].password;
      
      if (dbPassword == uPassword) {
        res.render("secrets.ejs")
      } else{
        res.send("inCorrect password")
      }
    } else{
      res.send("user does not exist, please register first")
    }
  } catch (error) {
    console.log(error);
    
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
