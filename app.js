//jshint esversion:6
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bcrypt from "bcrypt";
import flash from "express-flash";
import dotenv from "dotenv";

dotenv.config();
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
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
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

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      // console.log(profile);
      try {
        const user = await pool.query(
          "SELECT * FROM users WHERE google_id = $1",
          [profile._json.sub]
        );
        // console.log(user.rows[0]);
        if (user.rowCount > 0) {
          done(null, user.rows[0]);
        } else {
          try {
            const user = await pool.query(
              "INSERT INTO users(google_id) VALUES($1) RETURNING *",
              [profile._json.sub]
            );
            done(null, user.rows[0]);
          } catch (error) {
            console.log(error);

            done(error);
          }
        }
      } catch (error) {
        console.log(error);
        done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile"],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/login",
    successRedirect: "/secrets",
  })
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/secrets", ensureAuthenticated, (req, res) => {
  res.render("secrets.ejs");
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    // console.log(user);
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
