const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const app = express();
app.use(cors());
app.use(express.static("public"));
const CLIENT_ID = "8d9xvq5cp4vuvswuuap8";
const CLIENT_SECRET = "d5acf4c6b4194f8584673bd892f867c4";
const TUYA_HOST = "https://openapi.tuyaeu.com";
function hmacSHA256(secret, message) {
  return crypto.createHmac("sha256", secret).update(message).digest("hex").toUpperCase();
}
function sha256(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}
async function tuyaFetch(urlPath, token, method, body) {
  const t = Date.now().toString();
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const bodyStr = body ? JSON.stringify(body) : "";
  const bodyHash = sha256(bodyStr);
  const signStr = token
    ? CLIENT_ID + token + t + nonce + method + "\n" + bodyHash + "\n\n" + urlPath
    : CLIENT_ID + t + nonce + "GET\n" + bodyHash + "\n\n" + urlPath;
  const sign = hmacSHA256(CLIENT_SECRET, signStr);
  const headers = {
    "client_id": CLIENT_ID,
    "sign": sign,
    "t": t,
    "sign_method": "HMAC-SHA256",
    "nonce": nonce,
    "Content-Type": "application/json"
  };
  if (token) headers["access_token"] = token;
  const opts = { method: method || "GET", headers: headers };
  if (body) opts.body = bodyStr;
  const res = await fetch(TUYA_HOST + urlPath, opts);
  return res.json();
}
async function getToken() {
  const res = await tuyaFetch("/v1.0/token?grant_type=1");
  if (!res.success) throw new Error("Token: " + res.msg);
  return res.result.access_token;
}
app.get("/", function(req, res) {
  res.json({ status: "ok" });
});
app.get("/device/:id/status", async function(req, res) {
  try {
    const token = await getToken();
    const data = await tuyaFetch("/v1.0/devices/" + req.params.id + "/status", token, "GET", null);
    if (!data.success) return res.status(400).json(data);
    res.json(data.result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});
app.post("/device/:id/commands", async function(req, res) {
  try {
    const token = await getToken();
    const data = await tuyaFetch("/v1.0/devices/" + req.params.id + "/commands", token, "POST", req.body);
    if (!data.success) return res.status(400).json(data);
    res.json(data.result);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});
const PORT = process.env.PORT || 3001;
app.listen(PORT, function() {
  console.log("Server running on port " + PORT);
});
