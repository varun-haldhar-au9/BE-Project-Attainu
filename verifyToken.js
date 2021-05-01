const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  const TOKEN = req.header("auth-token");
  if (!TOKEN) return res.json("Access denied");
  try {
    const VERIFIED = jwt.verify(TOKEN, process.env.TOKEN_SECRET);
    req.user = VERIFIED;
    next();
  } catch (error) {
    return res.json("Invalid token");
  }
};
