const router = require("express").Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets");
const usersModel = require('../users/users-model'); // Adjust the path as necessary

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password, role_name } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12); // hash the password
    const user = await usersModel.add({ username, password: hashedPassword, role_name });
    res.status(201).json({ user_id: user.user_id, username: user.username, role_name: user.role_name });
  } catch (error) {
    next(error); // Pass errors to Express error handler
  }
});

router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const [user] = await usersModel.findBy({ username });
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({
        subject: user.user_id,
        username: user.username,
        role_name: user.role_name,
      }, JWT_SECRET, { expiresIn: '1d' }); // Token expires in 1 day
      res.status(200).json({ message: `${username} is back!`, token });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (error) {
    next(error);
  }
});

module.exports = router;
