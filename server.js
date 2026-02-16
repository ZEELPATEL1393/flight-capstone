const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  ScanCommand
} = require("@aws-sdk/lib-dynamodb");

const app = express();
app.use(cors());
app.use(express.json());

const REGION = process.env.AWS_REGION || "ca-central-1";

const client = new DynamoDBClient({ region: REGION });
const db = DynamoDBDocumentClient.from(client);

const USERS_TABLE = "Users";
const FLIGHTS_TABLE = "Flights";
const BOOKINGS_TABLE = "Bookings";

const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME";


// ================= ROOT ROUTE (CRITICAL FOR ELASTIC BEANSTALK)
app.get("/", (req, res) => {
  res.send("Flight API Running");
});


// ================= HEALTH ROUTE
app.get("/health", (req, res) => {
  res.json({ ok: true });
});


// ================= AUTH
function auth(role = null) {
  return (req, res, next) => {

    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : null;

    if (!token)
      return res.status(401).json({ error: "Missing token" });

    try {

      const decoded = jwt.verify(token, JWT_SECRET);

      req.user = decoded;

      if (role && decoded.role !== role)
        return res.status(403).json({ error: "Forbidden" });

      next();

    } catch {

      res.status(401).json({ error: "Invalid token" });

    }
  };
}


// ================= SIGNUP
app.post("/auth/signup", async (req, res) => {

  try {

    const { name, username, password, role } = req.body;

    const existing =
      await db.send(
        new GetCommand({
          TableName: USERS_TABLE,
          Key: { username }
        })
      );

    if (existing.Item)
      return res.status(409).json({ error: "Username exists" });

    const passwordHash =
      await bcrypt.hash(password, 10);

    await db.send(
      new PutCommand({
        TableName: USERS_TABLE,
        Item: {
          username,
          name,
          passwordHash,
          role: role === "admin" ? "admin" : "user"
        }
      })
    );

    res.json({ ok: true });

  } catch (e) {

    res.status(500).json({ error: e.message });

  }
});


// ================= LOGIN
app.post("/auth/login", async (req, res) => {

  try {

    const { username, password } = req.body;

    const user =
      await db.send(
        new GetCommand({
          TableName: USERS_TABLE,
          Key: { username }
        })
      );

    if (!user.Item)
      return res.status(401).json({ error: "Invalid" });

    const ok =
      await bcrypt.compare(password, user.Item.passwordHash);

    if (!ok)
      return res.status(401).json({ error: "Invalid" });

    const token =
      jwt.sign(
        {
          username,
          role: user.Item.role
        },
        JWT_SECRET,
        { expiresIn: "2h" }
      );

    res.json({ token, role: user.Item.role });

  } catch (e) {

    res.status(500).json({ error: e.message });

  }
});


// ================= GET FLIGHTS
app.get("/flights", auth(), async (req, res) => {

  const data =
    await db.send(
      new ScanCommand({
        TableName: FLIGHTS_TABLE
      })
    );

  res.json(data.Items || []);

});


// ================= ADD FLIGHT
app.post("/flights", auth("admin"), async (req, res) => {

  const { flightNo, destination, departure } = req.body;

  await db.send(
    new PutCommand({
      TableName: FLIGHTS_TABLE,
      Item: {
        flightNo,
        destination,
        departure
      }
    })
  );

  res.json({ ok: true });

});


// ================= BOOK FLIGHT
app.post("/bookings", auth("user"), async (req, res) => {

  const { flightNo } = req.body;

  await db.send(
    new PutCommand({
      TableName: BOOKINGS_TABLE,
      Item: {
        bookingId: uuidv4(),
        username: req.user.username,
        flightNo
      }
    })
  );

  res.json({ ok: true });

});


// ================= PORT (CRITICAL FIX)
const PORT = Number(process.env.PORT) || 8080;

app.listen(PORT, "0.0.0.0", () => {

  console.log("Server running on port", PORT);

});
