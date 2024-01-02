//jshint esversion:6
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import bcrypt from "bcrypt";
import flash from "express-flash";

const app = express();
const port = 3000;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.MY_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

const pool = new pg.Pool({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "senkao4813",
  port: 5432,
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await pool.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      const user = result.rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username." });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return done(null, false, { message: "Incorrect password." });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    done(null, user);
  } catch (error) {
    done(error);
  }
});

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login");
});

// app.get("/logout", (req, res) => {
//   res.redirect("/");
// });

app.get("/secrets", ensureAuthenticated, (req, res) => {
  res.render("secrets.ejs");
});

// app.post("/register", async (req, res) => {
//   const email = req.body.username;
//   const password = req.body.password;
//   try {
//     const result = await db.query(
//       "INSERT INTO users(email,password) VALUES($1, crypt($2, gen_salt('bf'))) ",
//       [email, password]
//     );
//     res.redirect("/login");
//   } catch (error) {
//     if (error.detail == "Key (email)=(1@2.com) already exists.") {
//       res.render("register", { error: "Email already exists." });
//     }
//   }
// });

// app.post("/login", async (req, res) => {
//   console.log(req.body);
//   const email = req.body.username;
//   const password = req.body.password;
//   try {
//     const result = await db.query(
//       "SELECT * FROM users WHERE email = $1 AND password = crypt($2, password)",
//       [email, password]
//     );
//     //console.log(result.rows);
//     if (result.rows == 0) {
//       res.render("login", {
//         error: "Please enter a valid email and password.",
//       });
//     } else {
//       res.redirect("/secrets");
//     }
//   } catch (error) {
//     console.log(error);
//   }
// });

// app.post(
//   "/login",
//   passport.authenticate("local", {
//     successRedirect: "/secrets",
//     failureRedirect: "/login",
//     failureFlash: true,
//   })
// );

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.render("login", {
        error: "Please enter a valid email and password.",
      });
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.redirect("/secrets");
    });
  })(req, res, next);
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await pool.query(
    "INSERT INTO users (email, password) VALUES ($1, $2) returning *",
    [username, hashedPassword]
  );
  req.login(user.rows[0], (err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/secrets");
  });
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    } else {
      res.redirect("/");
    }
  });
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

app.listen(port, () => {
  console.log(`Server listening at port: ${port}`);
});
