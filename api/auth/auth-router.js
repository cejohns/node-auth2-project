const router = require("express").Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets");
const usersModel = require('../users/users-model'); // Adjust the path as necessary

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    let { username, password, role_name = "student" } = req.body; // Default role_name handling
    // Trim username and role_name if not handled by middleware
    username = username.trim();

    if (!password) {
      return res.status(400).json({ message: "Password is required" });
    }

   role_name = role_name?.trim() || "default"; // Set your default role name here

    const hashedPassword = await bcrypt.hash(password, 12); // hash the password

    // You might need to adjust this to ensure the default role_id is used when role_name is not provided
    const user = await usersModel.add({ username, password: hashedPassword, role_name });
    
    // Adjust the response as necessary based on how your add function handles role_name and role_id mapping
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
      // JWT token generation happens only after verifying user credentials
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
    next(error); // Pass any errors to the error handling middleware
  }
});
 



module.exports = router;
