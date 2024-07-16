const express = require("express");
const cors = require("cors");
require("dotenv").config();
const bcrypt = require("bcrypt");
const { MongoClient, ServerApiVersion } = require("mongodb");
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

// Init PORT
const PORT = process.env.PORT || 8000;

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
      const salt = bcrypt.genSaltSync(16);
      const hasPass = bcrypt.hashSync(userInfo.pin, salt);
      const user = await userCollection.insertOne({
        ...userInfo,
        pin: hasPass,
      });

      res.status(201).json({ message: "User Created Successful", user });
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
