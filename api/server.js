const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
require('dotenv').config();


const authRouter = require("./auth/auth-router.js");
const usersRouter = require("./users/users-router.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use("/api/auth", authRouter);
server.use("/api/users", usersRouter);

server.use((err, req, res, next) => {
  res.status(err.status || 500).json({
    message: err.message,
    ...(process.env.NODE_ENV === 'development' ? { stack: err.stack } : {}),
  });
});


module.exports = server;
