const dotenv = require('dotenv').config();
const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  try {
    // extraction du token depuis le header authorization de la requête entrante
    // [1] correspond au 2ème élément du token splité, soit l'id client
    const token = req.headers.authorization.split(" ")[1];

    // décodage du token
    const decodedToken = jwt.verify(token, `${process.env.TOKEN}`);
    const userId = decodedToken.userId;
    if (req.body.userId && req.body.userId !== userId) {
      throw "Invalid user ID";
    } else {
      next();
    }
  } catch {
    res.status(401).json({
      error: new Error("Invalid request!"),
    });
  }
};
