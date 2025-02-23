require("dotenv").config();
const express = require("express");
const sanitizeHtml = require("sanitize-html");
var cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const db = require("better-sqlite3")("database.db");

const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
// make file accessible in server side
app.use(cookieParser());
app.use(express.static("public"));
const port = 3000;

// Enable Write-Ahead Logging for better concurrency
db.pragma("journal_mode = WAL");

// Database setup
const createTable = db.transaction(() => {
  db.prepare(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    );` // <-- Closing parenthesis and semicolon added
  ).run();
});

// Run the transaction to create the table
createTable();

// middleware
app.use(function (req, res, next) {
  res.locals.errors = [];

  // try to decode the incoming cookie
  try {
    const decoded = jwt.verify(req.cookies.OurSUperApp, process.env.JWTSECRET);
    req.user = decoded;
  } catch (error) {
    req.user = false;
  }

  res.locals.user = req.user;

  next();
});

app.get("/", (req, res) => {
  if (req.user) {
    return res.render("dashboard", { user: req.user });
  }
  res.render("home");
});

// logout route
app.get("/logout", (req, res) => {
  res.clearCookie("OurSUperApp");
  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  let errors = [];
  //  validate registration

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  if (req.body.username.trim() === "") errors.push("Invalid username / password provided");
  if (req.body.password === "") errors.push("Invalid username / password provided");

  if (errors.length) {
    return res.render("login", { errors });
  }

  // lookup the username in the database

  const usernameStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?");
  const resultUser = usernameStatement.get(req.body.username);

  if (!resultUser) {
    errors = ["Invalid username / password provided"];
    return res.render("login", { errors: errors });
  }

  const matchorNot = bcrypt.compareSync(req.body.password, resultUser.password);

  if (!matchorNot) {
    errors = ["Invalid username / password provided"];
    return res.render("login", { errors: errors });
  }

  const tokenValue = jwt.sign(
    { exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userId: resultUser.id, username: resultUser.username },
    process.env.JWTSECRET
  );

  res.cookie("OurSUperApp", tokenValue, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 1000 * 60 * 60 * 24 });

  res.redirect("/");
});

app.post("/register", (req, res) => {
  const errors = [];
  //  validate registration

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();
  req.body.password = req.body.password.trim();

  if (!req.body.username) errors.push("Username is required");
  if (req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters");
  if (req.body.username && req.body.username.length > 10) errors.push("Username must be less than 10 characters");
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters");

  // check if username exists already

  const usernameStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?");
  const usernameCheck = usernameStatement.get(req.body.username);

  if (usernameCheck) errors.push("Username already taken");

  if (!req.body.password) errors.push("Password is required");
  if (req.body.username && req.body.password.length < 8) errors.push("Password must be at least 8 characters");
  if (req.body.password && req.body.password.length > 70) errors.push("Password must be less than 70 characters");

  if (errors.length) {
    return res.render("home", { errors });
  }

  // save the new user into database
  try {
    // hash password

    const salt = bcrypt.genSaltSync(10);
    req.body.password = bcrypt.hashSync(req.body.password, salt);

    const insertQuery = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    const result = insertQuery.run(req.body.username, req.body.password);
    console.log("User inserted successfully!");

    const lookUp = db.prepare("SELECT username FROM users WHERE ROWID =?");

    const ouruser = lookUp.get(result.lastInsertRowid);

    // log the user in by assigning a cookie

    const tokenValue = jwt.sign(
      { exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userId: ouruser.id, username: ouruser.username },
      process.env.JWTSECRET
    );

    res.cookie("OurSUperApp", tokenValue, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 1000 * 60 * 60 * 24 });
  } catch (error) {
    console.error("Error inserting user:", error);
  }

  return res.redirect("/");
});

//  create post request routes

function mustBeLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect("/");
}
app.get("/create-post", mustBeLoggedIn, (req, res) => {
  return res.render("create-post");
});
app.post("/create-post", mustBeLoggedIn, (req, res) => {
  const errors = sharedPostValidation(req);
});

function sharedPostValidation(req) {
  const errors = [];
  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.title = "";

  // trim - sanitize or strip out html

  return errors;
}
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
