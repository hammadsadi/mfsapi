const express = require("express");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
// Init Express
const app = express();

// Global Middleware
app.use(express.json());

// init Cors
app.use(
  cors({
    origin: ["http://localhost:5173", "https://mfs-sadi.netlify.app"],
    credentials: true,
  })
);
app.use(cookieParser());

// Init PORT
const PORT = process.env.PORT || 8000;

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
    const sendMoneyCollection = client.db("mfsDB").collection("sendMoneys");

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

    /**
     * Admin Related API
     */
    // Get All User
    app.get("/users/all", tokenVerify, async (req, res) => {
      const users = await userCollection.find().toArray();
      res.send(users);
    });

    // Get Admin
    app.get("/admin/:email", tokenVerify, async (req, res) => {
      const { email } = req.params;
      if (req.user.email !== email) {
        return res.status(403).json({ message: "Unauthorized Access" });
      }
      const user = await userCollection.findOne({ email: email });
      let admin = false;
      if (user) {
        admin = user.accountType === "admin";
      }

      res.send(admin);
    });
    // Get Agent
    app.get("/agent/:email", tokenVerify, async (req, res) => {
      const { email } = req.params;
      if (req.user.email !== email) {
        return res.status(403).json({ message: "Unauthorized Access" });
      }
      const user = await userCollection.findOne({ email: email });
      let agent = false;
      if (user) {
        agent = user.accountType === "agent";
      }

      res.send(agent);
    });

    /**
     * User Related Api
     */

    // Update User Account Status
    app.put("/users/status/:id", tokenVerify, async (req, res) => {
      const id = req.params.id;
      const { status, balance, prevStatus } = req.body;
      const query = { _id: new ObjectId(id) };
      if (status == "active" && prevStatus == "pending") {
        const updateDoc = {
          $set: {
            status: "active",
            balance: 40,
          },
        };

        const users = await userCollection.updateOne(query, updateDoc);
        res.send(users);
      }
      if (status == "block") {
        const updateDoc = {
          $set: {
            status: "block",
            balance,
          },
        };

        const users = await userCollection.updateOne(query, updateDoc);
        res.send(users);
      }
      if (status == "active" && prevStatus == "block") {
        const updateDoc = {
          $set: {
            status: "active",
            balance,
          },
        };

        const users = await userCollection.updateOne(query, updateDoc);
        res.send(users);
      }
    });

    // Send Money
    app.post("/send-money", tokenVerify, async (req, res) => {
      const transactionInfo = req.body;

      const findReciver = await userCollection.findOne({
        mobile: transactionInfo?.receiverMobile,
      });

      // Check Reciver
      if (!findReciver) return res.send({ error: "Receiver Not Found" });

      // Match Password
      const checkPass = bcrypt.compareSync(
        transactionInfo?.pin,
        findReciver.pin
      );
      if (!checkPass) {
        return res.send({ error: "Wrong PIN" });
      }

      // Success Money
      const successMoney = await sendMoneyCollection.insertOne({
        ...transactionInfo,
        pin: null,
      });

      // Update Sender Money
      const senderSuccessMoney = await userCollection.updateOne(
        {
          email: transactionInfo?.senderInfo?.email,
        },
        { $inc: { balance: -transactionInfo.amount } }
      );

      // Update Sender Money
      const ReciverSuccessMoney = await userCollection.updateOne(
        {
          mobile: transactionInfo?.receiverMobile,
        },
        { $inc: { balance: +transactionInfo.amount } }
      );

      res.send({ message: "Send Money Success Completed" });
    });

    // Get All Transaction
    app.get("/all-user-transaction", tokenVerify, async (req, res) => {
      const findReciver = await sendMoneyCollection.find().toArray();

      res.send(findReciver);
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
