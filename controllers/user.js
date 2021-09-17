const dotenv = require('dotenv').config();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


//------------------------------------------------------
// créer un nouvel utilisateur
//------------------------------------------------------
exports.signup = (req, res, next) => {
  // cryptage du mot de passe
  bcrypt
    .hash(req.body.password, 10) // saler 10 fois
    .then((hash) => {
      // nouvel utilisateur avec les valeurs reçues
      const user = new User({
        email: req.body.email,
        password: hash,
      });
      // enregistrement de l'utilisateur dans la base de données
      user
        .save()
        .then(() => res.status(201).json({ message: "Utilisateur créé !" }))
        .catch((error) => res.status(400).json({ error }));
    })
    .catch((error) => res.status(500).json({ error }));
};

//------------------------------------------------------
// se connecter
//------------------------------------------------------
exports.login = (req, res, next) => {
  // recherche de l'utilisateur dans la base de données
  User.findOne({ email: req.body.email })
    .then((user) => {
      // si l'utilisateur n'existe pas
      if (!user) {
        return res.status(401).json({ error: "Utilisateur non trouvé !" });
      }
      //s'il existe on compare (méthode compare() de bcrypt) le hash avec saisi avec celui de la base de données
      bcrypt
        .compare(req.body.password, user.password)
        .then((valid) => {
          // si il n'est pas valide
          if (!valid) {
            return res.status(401).json({ error: "Mot de passe incorrect !" });
          }
          // si il est valide
          res.status(200).json({
            userId: user._id,
            token: jwt.sign({ userId: user._id }, `${process.env.TOKEN}`, { expiresIn: "24h" }),
          });
        })
        .catch((error) => res.status(500).json({ error }));
    })
    .catch((error) => res.status(500).json({ error }));
};