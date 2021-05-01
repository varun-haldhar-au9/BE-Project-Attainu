const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();

const app = express();

const { registerValidation, loginValidation } = require("./validation");

// User Model
const User = require("./models/User");

// MongoDB Connection
mongoose.connect(
  process.env.CONNECTION_URL,
  { useNewUrlParser: true, useUnifiedTopology: true },
  () => console.log("Connected to DB")
);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

app.get("/", (req, res) => {
  res.send("Health OK");
});

// Register User
app.post("/register", async (req, res) => {
  // Validate Data
  const { error } = registerValidation(req.body);
  if (error) return res.json(error.details[0].message);

  //   Checking Duplicate Email
  const emailExist = await User.findOne({ email: req.body.email });
  if (emailExist) return res.json("Email already exist");

  //   Hashing password
  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(req.body.password, salt);

  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashPassword,
    role: req.body.role ? req.body.role : "user",
    isActive: req.body.isActive ? req.body.isActive : true,
  });

  try {
    const savedUser = await user.save();
    res.send({ id: savedUser._id });
  } catch (error) {
    res.send(err);
  }
});

// Login User
app.post("/login", async (req, res) => {
  // Validate Data
  const { error } = loginValidation(req.body);
  if (error) return res.json(error.details[0].message);

  //   Checking Duplicate Email
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.json("Email not found");

  //   Checking Password
  const validPassword = bcrypt.compareSync(req.body.password, user.password);
  if (!validPassword) return res.json("Invalid password");

  //   Create and assign token
  const TOKEN = jwt.sign({ user }, process.env.TOKEN_SECRET);
  res.header("auth-token", TOKEN).json(TOKEN);
});

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => console.log("Server is up and running on " + PORT));
