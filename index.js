const express = require("express");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion } = require("mongodb");
const jwt = require("jsonwebtoken");
// Init Express
const app = express();

// Global Middleware
app.use(express.json());

// init Cors
app.use(
  cors({
    origin: ["http://localhost:5173"],
    credentials: true,
  })
);
app.use(cookieParser());

// Init PORT
const PORT = process.env.PORT || 8000;

// const tokenVerify = (req, res, next) => {
//   try {
//     const token = req.cookies.token;
//     if (!token) {
//       return res.status(401).send("Unauthorized Access");
//     }
//     next();
//     if (token) {
//       jwt.verify(token, process.env.SCREET_KEY, (err, decode) => {
//         if (err) {
//           console.log(err);
//           return res.status(401).send("Unauthorized Access");
//         }
//         req.user = decode;
//         next();
//       });
//     }

//     next();
//   } catch (error) {
//     console.log(error);
//   }
// };

// Token Verify
const tokenVerify = (req, res, next) => {
  const token = req?.cookies?.token;
  if (!token) {
    return res.status(401).send("Unauthorized Access");
  }
  jwt.verify(token, process.env.SCREET_KEY, (err, decode) => {
    if (err) {
      return res.status(401).send("Unauthorized Access");
    }
    req.user = decode;
    next();
  });
};

// Db Connect

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@syedsadibd.a5hvdhf.mongodb.net/?retryWrites=true&w=majority&appName=syedsadibd`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const userCollection = client.db("mfsDB").collection("users");

    // Create User
    app.post("/user", async (req, res) => {
      const userInfo = req.body;
      // Check User
      const existUser = await userCollection.findOne({ email: userInfo.email });
      if (existUser) {
        return res.status(400).json({ error: "User Already Exists" });
      }
      // Sal Create
      const salt = bcrypt.genSaltSync(16);
      // Hash Password
      const hasPass = bcrypt.hashSync(userInfo.pin, salt);
      const user = await userCollection.insertOne({
        ...userInfo,
        pin: hasPass,
      });

      res.status(201).json({ message: "User Created Successful", user });
    });

    // Login User

    app.post("/user/login", async (req, res) => {
      const userInfo = req.body;
      // Check User
      const existUserByEmail = await userCollection.findOne({
        email: userInfo.numberAndEmail,
      });
      const existUserByMobile = await userCollection.findOne({
        mobile: userInfo.numberAndEmail,
      });

      if (!existUserByEmail && !existUserByMobile) {
        return res.status(400).json({ error: "Invalid Information" });
      }
      const dbPass = existUserByEmail ? existUserByEmail : existUserByMobile;
      // Match Password
      const checkPass = bcrypt.compareSync(userInfo?.pin, dbPass.pin);
      if (!checkPass) {
        return res.status(400).json({ error: "Invalid Information" });
      }

      // Token Genarate
      const UserCrendential = { email: userInfo?.numberAndEmail };
      // const token = jwt.sign(
      //   { email: userInfo?.numberAndEmail },
      //   process.env.SCREET_KEY,
      //   { expiresIn: "1h" }
      // );
      const token = jwt.sign(UserCrendential, process.env.SCREET_KEY, {
        expiresIn: "1h",
      });

      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      });

      res.status(201).json({ message: "User Login Successful" });
    });

    // Logout User
    app.get("/user/logout", async (req, res) => {
      try {
        res.clearCookie("token", {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          maxAge: 0,
        });
        res.status(200).json({ message: "User Logout Successful" });
      } catch (error) {
        console.log(error);
      }
    });

    // Get Logged in  User
    app.get("/logged/in/user", tokenVerify, async (req, res) => {
      const mail = req.user.email;
      // Check User
      const existUserByEmail = await userCollection.findOne({
        email: mail,
      });
      const existUserByMobile = await userCollection.findOne({
        mobile: mail,
      });

      const loggedUser = existUserByEmail
        ? existUserByEmail
        : existUserByMobile;

      res.send(loggedUser);
    });

    // Get All User
    app.get("/users/all", tokenVerify, async (req, res) => {
      console.log(req.user);
      const users = await userCollection.find().toArray();
      res.send(users);
    });

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// Get Basic
app.get("/", async (req, res) => {
  res.send("Server is Running");
});

// Listen Server
app.listen(PORT, () => {
  console.log(`Server Is Running on PORT ${PORT}`);
});
