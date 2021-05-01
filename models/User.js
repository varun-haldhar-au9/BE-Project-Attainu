const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    require: true,
    min: 6,
    max: 25,
  },
  email: {
    type: String,
    require: true,
    min: 6,
    max: 254,
  },
  password: {
    type: String,
    require: true,
    min: 6,
    max: 254,
  },
  role: {
    type: String,
    require: true,
  },
  isActive: {
    type: String,
    require: true,
  },
  date: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("User", userSchema);
