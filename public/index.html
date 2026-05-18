const express    = require("express");
const cors       = require("cors");
const crypto     = require("crypto");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const path       = require("path");

const app = express();
app.use(cors());
app.use(express.json());

// ── CONFIG ──
const MONGO_URI     = process.env.MONGO_URI     || "mongodb+srv://costantinotomasi:Lorenzo2021@appgb.rshzn7i.mongodb.net/domotica?appName=AppGB";
const JWT_SECRET    = process.env.JWT_SECRET    || "domotica_secret_2024";
const TUYA_HOST     = "https://openapi.tuyaeu.com";

// ── MONGODB ──
mongoose.connect(MONGO_URI)
  .then(() => console.log("MongoDB connesso"))
  .catch(e => console.error("MongoDB errore:", e.message));

// ── SCHEMAS ──

// Utente
const UserSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  email:     { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  role:      { type: String, enum: ["admin", "client"], default: "client" },
  createdAt: { type: Date, default: Date.now }
});

// Dispositivo
const DeviceSchema = new mongoose.Schema({
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  name:        { type: String, required: true },
  deviceId:    { type: String, required: true },
  type:        { type: String, enum: ["counter", "valve", "sensor", "other"], default: "counter" },
  room:        { type: String, default: "Generale" },
  tuyaClientId:     { type: String },
  tuyaClientSecret: { type: String },
  active:      { type: Boolean, default: true },
  createdAt:   { type: Date, default: Date.now }
});

const User   = mongoose.model("User",   UserSchema);
const Device = mongoose.model("Device", DeviceSchema);

// ── TUYA HELPERS ──
function hmacSHA256(secret, message) {
  return crypto.createHmac("sha256", secret).update(message).digest("hex").toUpperCase();
}
function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

async function tuyaFetch(clientId, clientSecret, urlPath, token, method, body) {
  const t        = Date.now().toString();
  const nonce    = crypto.randomUUID().replace(/-/g, "");
  const bodyStr  = body ? JSON.stringify(body) : "";
  const bodyHash = sha256(bodyStr);
  const signStr  = token
    ? clientId + token + t + nonce + method + "\n" + bodyHash + "\n\n" + urlPath
    : clientId + t + nonce + "GET\n" + bodyHash + "\n\n" + urlPath;
  const sign = hmacSHA256(clientSecret, signStr);
  const headers = {
    "client_id":    clientId,
    "sign":         sign,
    "t":            t,
    "sign_method":  "HMAC-SHA256",
    "nonce":        nonce,
    "Content-Type": "application/json"
  };
  if (token) headers["access_token"] = token;
  const opts = { method: method || "GET", headers };
  if (body) opts.body = bodyStr;
  const res = await fetch(TUYA_HOST + urlPath, opts);
  return res.json();
}

async function getTuyaToken(clientId, clientSecret) {
  const res = await tuyaFetch(clientId, clientSecret, "/v1.0/token?grant_type=1", null, "GET", null);
  if (!res.success) throw new Error("Token Tuya: " + res.msg);
  return res.result.access_token;
}

// ── AUTH MIDDLEWARE ──
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ error: "Non autorizzato" });
  try {
    req.user = jwt.verify(auth.split(" ")[1], JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: "Token non valido" });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Solo admin" });
  next();
}

// ════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Email o password errati" });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Email o password errati" });
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: "30d" });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════
// ADMIN ROUTES
// ════════════════════════════════════════

// Lista utenti (solo admin)
app.get("/admin/users", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await User.find({}, "-password");
    res.json(users);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Crea utente (solo admin)
app.post("/admin/users", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: "Email già esistente" });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash, role: role || "client" });
    res.json({ id: user._id, name: user.name, email: user.email, role: user.role });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Elimina utente (solo admin)
app.delete("/admin/users/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    await Device.deleteMany({ userId: req.params.id });
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Lista tutti i dispositivi (solo admin)
app.get("/admin/devices", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const devices = await Device.find().populate("userId", "name email");
    res.json(devices);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Crea dispositivo per un utente (solo admin)
app.post("/admin/devices", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { userId, name, deviceId, type, room, tuyaClientId, tuyaClientSecret } = req.body;
    const device = await Device.create({ userId, name, deviceId, type, room, tuyaClientId, tuyaClientSecret });
    res.json(device);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Elimina dispositivo (solo admin)
app.delete("/admin/devices/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await Device.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ════════════════════════════════════════
// CLIENT ROUTES
// ════════════════════════════════════════

// Lista dispositivi dell'utente
app.get("/devices", authMiddleware, async (req, res) => {
  try {
    const devices = await Device.find({ userId: req.user.id, active: true }, "-tuyaClientSecret");
    res.json(devices);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Stato dispositivo
app.get("/devices/:id/status", authMiddleware, async (req, res) => {
  try {
    const device = await Device.findOne({ _id: req.params.id, userId: req.user.id });
    if (!device) return res.status(404).json({ error: "Dispositivo non trovato" });
    const clientId     = device.tuyaClientId     || "8d9xvq5cp4vuvswuuap8";
    const clientSecret = device.tuyaClientSecret || "d5acf4c6b4194f8584673bd892f867c4";
    const token = await getTuyaToken(clientId, clientSecret);
    const data  = await tuyaFetch(clientId, clientSecret, "/v1.0/devices/" + device.deviceId + "/status", token, "GET", null);
    if (!data.success) return res.status(400).json(data);
    res.json(data.result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Comando dispositivo
app.post("/devices/:id/commands", authMiddleware, async (req, res) => {
  try {
    const device = await Device.findOne({ _id: req.params.id, userId: req.user.id });
    if (!device) return res.status(404).json({ error: "Dispositivo non trovato" });
    const clientId     = device.tuyaClientId     || "8d9xvq5cp4vuvswuuap8";
    const clientSecret = device.tuyaClientSecret || "d5acf4c6b4194f8584673bd892f867c4";
    console.log("COMANDO:", device.name, JSON.stringify(req.body));
    const token = await getTuyaToken(clientId, clientSecret);
    const data  = await tuyaFetch(clientId, clientSecret, "/v1.0/devices/" + device.deviceId + "/commands", token, "POST", req.body);
    console.log("RISPOSTA:", JSON.stringify(data));
    if (!data.success) return res.status(400).json(data);
    res.json(data.result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── SERVE PWA ──
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ── START ──
const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  console.log("Server running on port " + PORT);
  // Crea admin di default se non esiste
  try {
    const exists = await User.findOne({ role: "admin" });
    if (!exists) {
      const hash = await bcrypt.hash("admin123", 10);
      await User.create({ name: "Admin", email: "admin@domotica.it", password: hash, role: "admin" });
      console.log("Admin creato: admin@domotica.it / admin123");
    }
  } catch(e) {
    console.log("Errore creazione admin:", e.message);
  }
});
