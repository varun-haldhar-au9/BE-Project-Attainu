const JOI = require("joi");

// Register Validation
const registerValidation = (user) => {
  const schema = JOI.object({
    name: JOI.string().min(6).required(),
    email: JOI.string().min(6).email().required(),
    password: JOI.string().min(5).required(),
    role: JOI.string(),
    isActive: JOI.string(),
  });
  return schema.validate(user);
};

// Login Validation
const loginValidation = (user) => {
  const schema = JOI.object({
    email: JOI.string().email().min(6).required(),
    password: JOI.string().min(5).required(),
  });
  return schema.validate(user);
};

module.exports = { registerValidation, loginValidation };
