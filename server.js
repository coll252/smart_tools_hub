require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const sharp = require("sharp");
const QRCode = require("qrcode");
const { PDFDocument } = require("pdf-lib");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");

const app = express();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

const uploadDir = path.join(__dirname, "uploads");
const publicDir = path.join(__dirname, "public");

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// IMPORTANT: static files
app.use(express.static(publicDir));

// Rate limit
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 150
  })
);

const upload = multer({ dest: uploadDir });

let db;

// ================= DB =================
async function connectDB() {
  db = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT || 3306),
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : undefined
  });

  console.log("MySQL connected");
}

// ================= DEBUG ROUTE =================
app.get("/api/check-file", (req, res) => {
  const indexPath = path.join(publicDir, "index.html");

  res.json({
    publicDir,
    indexPath,
    exists: fs.existsSync(indexPath)
  });
});

// ================= HEALTH =================
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

// ================= HOMEPAGE =================
app.get("/", (req, res) => {
  const file = path.join(publicDir, "index.html");

  if (fs.existsSync(file)) {
    res.sendFile(file);
  } else {
    res.status(500).send("index.html not found in /public folder");
  }
});

// ================= TOOLS =================
app.post("/api/tools/password", (req, res) => {
  const length = Math.min(Number(req.body.length || 16), 64);
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=";

  let password = "";
  for (let i = 0; i < length; i++) {
    password += chars[Math.floor(Math.random() * chars.length)];
  }

  res.json({ password });
});

app.post("/api/tools/qr", async (req, res) => {
  try {
    const { text } = req.body;

    if (!text) return res.status(400).json({ error: "Text required" });

    const qrImage = await QRCode.toDataURL(text);

    res.json({ qrImage });
  } catch {
    res.status(500).json({ error: "QR failed" });
  }
});

app.post("/api/tools/text-stats", (req, res) => {
  const text = req.body.text || "";

  res.json({
    words: text.split(/\s+/).filter(Boolean).length,
    characters: text.length
  });
});

// ================= FALLBACK (VERY IMPORTANT) =================
app.use((req, res) => {
  const file = path.join(publicDir, "index.html");

  if (fs.existsSync(file)) {
    res.sendFile(file);
  } else {
    res.status(404).send("Not Found - index.html missing");
  }
});

// ================= START =================
connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error(err);
    process.exit(1);
  });
