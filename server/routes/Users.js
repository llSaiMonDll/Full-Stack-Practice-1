const express = require("express");
const router = express.Router();
const { Users } = require("../models");
const bcrypt = require("bcrypt");

const { sign } = require("jsonwebtoken");
const { validateToken } = require("../middlewares/AuthMiddleware");

router.post("/", async (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10).then((hash) => {
    Users.create({
      username: username,
      password: hash,
    });
    res.json("SUCCESS");
  });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await Users.findOne({
    where: {
      username: username,
    },
  });

  if (user) {
    bcrypt.compare(password, user.password).then((same) => {
      if (!same) {
        return res.json({ error: "Wrong username or password" });
      } else {
        const accessToken = sign(
          { username: user.username, id: user.id },
          "importantsecret"
        );

        return res.json({
          token: accessToken,
          username: username,
          id: user.id,
        });
      }
    });
  } else {
    return res.json({ error: "User doesn't exist" });
  }
});

router.get("/auth", validateToken, (req, res) => {
  res.json(req.user);
});

router.get("/basicinfo/:id", async (req, res) => {
  const id = req.params.id;

  const basicInfo = await Users.findByPk(id, {
    attributes: { exclude: ["password"] },
  });
  res.json(basicInfo);
});

router.put("/changepassword", validateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = await Users.findOne({
    where: {
      username: req.user.username,
    },
  });
  if (user) {
    bcrypt.compare(oldPassword, user.password).then((same) => {
      if (!same) {
        return res.json({ error: "Wrong Password Entered!" });
      } else {
        bcrypt.hash(newPassword, 10).then( (hash) => {
         Users.update(
            { password: hash },
            {
              where: {
                username: req.user.username,
              },
            }
          );
          res.json("SUCCESS");
        });
      }
    });
  } else {
    return res.json({ error: "User doesn't exist" });
  }
});
module.exports = router;
