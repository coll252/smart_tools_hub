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
const FREE_DAILY_LIMIT = Number(process.env.FREE_DAILY_LIMIT || 20);
const PREMIUM_DAILY_LIMIT = Number(process.env.PREMIUM_DAILY_LIMIT || 1000);
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 20);

const uploadDir = path.join(__dirname, "uploads");
const publicDir = path.join(__dirname, "public");

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicDir));

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 150,
    message: { error: "Too many requests. Try again later." }
  })
);

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: MAX_UPLOAD_MB * 1024 * 1024
  }
});

let db;

async function connectDB() {
  const sslEnabled = process.env.DB_SSL === "true";

  db = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT || 3306),
    waitForConnections: true,
    connectionLimit: 10,
    ssl: sslEnabled ? { rejectUnauthorized: false } : undefined
  });

  console.log("MySQL connected");

  await createTables();
}

async function createTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      uuid VARCHAR(100) UNIQUE NOT NULL,
      name VARCHAR(150) NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role ENUM('user','admin') DEFAULT 'user',
      plan ENUM('free','premium') DEFAULT 'free',
      is_active BOOLEAN DEFAULT true,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS tool_usage (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      tool_name VARCHAR(100) NOT NULL,
      ip_address VARCHAR(100),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      checkout_request_id VARCHAR(150),
      merchant_request_id VARCHAR(150),
      phone VARCHAR(50),
      amount DECIMAL(10,2),
      status ENUM('pending','success','failed') DEFAULT 'pending',
      raw_response JSON NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS feedback (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      name VARCHAR(150),
      email VARCHAR(150),
      message TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    )
  `);
}

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      plan: user.plan
    },
    JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
  );
}

async function authOptional(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header) {
      req.user = null;
      return next();
    }

    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const [rows] = await db.query(
      "SELECT id, uuid, name, email, role, plan, is_active FROM users WHERE id = ?",
      [decoded.id]
    );

    req.user = rows[0] || null;
    next();
  } catch {
    req.user = null;
    next();
  }
}

async function authRequired(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header) {
      return res.status(401).json({ error: "Login required" });
    }

    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const [rows] = await db.query(
      "SELECT id, uuid, name, email, role, plan, is_active FROM users WHERE id = ?",
      [decoded.id]
    );

    if (!rows.length || !rows[0].is_active) {
      return res.status(401).json({ error: "Invalid account" });
    }

    req.user = rows[0];
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

async function checkToolLimit(req, res, next) {
  try {
    const userId = req.user?.id || null;
    const ip = req.ip;
    const limit =
      req.user?.plan === "premium" ? PREMIUM_DAILY_LIMIT : FREE_DAILY_LIMIT;

    let rows;

    if (userId) {
      [rows] = await db.query(
        "SELECT COUNT(*) AS total FROM tool_usage WHERE user_id = ? AND DATE(created_at) = CURDATE()",
        [userId]
      );
    } else {
      [rows] = await db.query(
        "SELECT COUNT(*) AS total FROM tool_usage WHERE ip_address = ? AND DATE(created_at) = CURDATE()",
        [ip]
      );
    }

    if (rows[0].total >= limit) {
      return res.status(429).json({
        error: "Daily limit reached. Upgrade to premium."
      });
    }

    next();
  } catch {
    res.status(500).json({ error: "Limit check failed" });
  }
}

async function logToolUsage(req, toolName) {
  await db.query(
    "INSERT INTO tool_usage (user_id, tool_name, ip_address) VALUES (?, ?, ?)",
    [req.user?.id || null, toolName, req.ip]
  );
}

function safeDelete(filePath) {
  if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
}

app.get("/", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    app: "SmartTools Hub",
    environment: process.env.NODE_ENV
  });
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      "INSERT INTO users (uuid, name, email, password) VALUES (?, ?, ?, ?)",
      [uuidv4(), name, email, hashed]
    );

    const [rows] = await db.query(
      "SELECT id, uuid, name, email, role, plan FROM users WHERE id = ?",
      [result.insertId]
    );

    const token = signToken(rows[0]);

    res.json({
      message: "Account created successfully",
      token,
      user: rows[0]
    });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ error: "Email already exists" });
    }

    res.status(500).json({ error: "Signup failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [
      email
    ]);

    if (!rows.length) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const cleanUser = {
      id: user.id,
      uuid: user.uuid,
      name: user.name,
      email: user.email,
      role: user.role,
      plan: user.plan
    };

    res.json({
      message: "Login successful",
      token: signToken(cleanUser),
      user: cleanUser
    });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

app.post(
  "/api/tools/password",
  authOptional,
  checkToolLimit,
  async (req, res) => {
    const length = Math.min(Number(req.body.length || 16), 64);
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=";

    let password = "";

    for (let i = 0; i < length; i++) {
      password += chars[Math.floor(Math.random() * chars.length)];
    }

    await logToolUsage(req, "password-generator");

    res.json({ password });
  }
);

app.post("/api/tools/qr", authOptional, checkToolLimit, async (req, res) => {
  try {
    const { text } = req.body;

    if (!text) return res.status(400).json({ error: "Text is required" });

    const qrImage = await QRCode.toDataURL(text, {
      width: 350,
      margin: 2
    });

    await logToolUsage(req, "qr-generator");

    res.json({ qrImage });
  } catch {
    res.status(500).json({ error: "QR generation failed" });
  }
});

app.post(
  "/api/tools/text-stats",
  authOptional,
  checkToolLimit,
  async (req, res) => {
    const text = req.body.text || "";

    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    const characters = text.length;
    const charactersNoSpaces = text.replace(/\s/g, "").length;
    const sentences = text.split(/[.!?]+/).filter(Boolean).length;
    const paragraphs = text.split(/\n+/).filter(Boolean).length;
    const readingTime = Math.ceil(words / 200);

    await logToolUsage(req, "word-counter");

    res.json({
      words,
      characters,
      charactersNoSpaces,
      sentences,
      paragraphs,
      readingTime
    });
  }
);

app.post(
  "/api/tools/case-converter",
  authOptional,
  checkToolLimit,
  async (req, res) => {
    const text = req.body.text || "";
    const mode = req.body.mode || "upper";

    let output = text;

    if (mode === "upper") output = text.toUpperCase();
    if (mode === "lower") output = text.toLowerCase();
    if (mode === "title") {
      output = text.toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
    }
    if (mode === "sentence") {
      output = text
        .toLowerCase()
        .replace(/(^\s*\w|[.!?]\s*\w)/g, c => c.toUpperCase());
    }

    await logToolUsage(req, "case-converter");

    res.json({ output });
  }
);

app.post(
  "/api/tools/image-compress",
  authOptional,
  checkToolLimit,
  upload.single("image"),
  async (req, res) => {
    let outputPath;

    try {
      if (!req.file) return res.status(400).json({ error: "Image required" });

      const quality = Math.min(Math.max(Number(req.body.quality || 65), 10), 95);
      outputPath = path.join(uploadDir, `compressed-${Date.now()}.jpg`);

      await sharp(req.file.path).jpeg({ quality }).toFile(outputPath);

      await logToolUsage(req, "image-compressor");

      safeDelete(req.file.path);

      res.download(outputPath, "compressed-image.jpg", () => {
        safeDelete(outputPath);
      });
    } catch {
      safeDelete(req.file?.path);
      safeDelete(outputPath);
      res.status(500).json({ error: "Image compression failed" });
    }
  }
);

app.post(
  "/api/tools/image-resize",
  authOptional,
  checkToolLimit,
  upload.single("image"),
  async (req, res) => {
    let outputPath;

    try {
      if (!req.file) return res.status(400).json({ error: "Image required" });

      const width = Number(req.body.width || 800);
      const height = Number(req.body.height || 800);

      outputPath = path.join(uploadDir, `resized-${Date.now()}.jpg`);

      await sharp(req.file.path)
        .resize(width, height, { fit: "inside" })
        .jpeg({ quality: 80 })
        .toFile(outputPath);

      await logToolUsage(req, "image-resizer");

      safeDelete(req.file.path);

      res.download(outputPath, "resized-image.jpg", () => {
        safeDelete(outputPath);
      });
    } catch {
      safeDelete(req.file?.path);
      safeDelete(outputPath);
      res.status(500).json({ error: "Image resize failed" });
    }
  }
);

app.post(
  "/api/tools/pdf-merge",
  authOptional,
  checkToolLimit,
  upload.array("pdfs", 10),
  async (req, res) => {
    let outputPath;

    try {
      if (!req.files || req.files.length < 2) {
        return res.status(400).json({ error: "Upload at least 2 PDFs" });
      }

      const mergedPdf = await PDFDocument.create();

      for (const file of req.files) {
        const bytes = fs.readFileSync(file.path);
        const pdf = await PDFDocument.load(bytes);
        const pages = await mergedPdf.copyPages(pdf, pdf.getPageIndices());
        pages.forEach(page => mergedPdf.addPage(page));
      }

      const mergedBytes = await mergedPdf.save();

      outputPath = path.join(uploadDir, `merged-${Date.now()}.pdf`);
      fs.writeFileSync(outputPath, mergedBytes);

      await logToolUsage(req, "pdf-merger");

      req.files.forEach(file => safeDelete(file.path));

      res.download(outputPath, "merged.pdf", () => {
        safeDelete(outputPath);
      });
    } catch {
      req.files?.forEach(file => safeDelete(file.path));
      safeDelete(outputPath);
      res.status(500).json({ error: "PDF merge failed" });
    }
  }
);

app.post("/api/feedback", authOptional, async (req, res) => {
  try {
    const { name, email, message } = req.body;

    if (!message) return res.status(400).json({ error: "Message required" });

    await db.query(
      "INSERT INTO feedback (user_id, name, email, message) VALUES (?, ?, ?, ?)",
      [req.user?.id || null, name || null, email || null, message]
    );

    res.json({ message: "Feedback sent successfully" });
  } catch {
    res.status(500).json({ error: "Feedback failed" });
  }
});

app.get("/api/admin/stats", authRequired, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }

  const [[users]] = await db.query("SELECT COUNT(*) AS total FROM users");
  const [[premium]] = await db.query(
    "SELECT COUNT(*) AS total FROM users WHERE plan='premium'"
  );
  const [[usage]] = await db.query("SELECT COUNT(*) AS total FROM tool_usage");

  const [popularTools] = await db.query(`
    SELECT tool_name, COUNT(*) AS total
    FROM tool_usage
    GROUP BY tool_name
    ORDER BY total DESC
    LIMIT 10
  `);

  res.json({
    users: users.total,
    premiumUsers: premium.total,
    toolUsage: usage.total,
    popularTools
  });
});

async function getMpesaAccessToken() {
  const auth = Buffer.from(
    `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
  ).toString("base64");

  const baseUrl =
    process.env.MPESA_ENV === "production"
      ? "https://api.safaricom.co.ke"
      : "https://sandbox.safaricom.co.ke";

  const response = await axios.get(
    `${baseUrl}/oauth/v1/generate?grant_type=client_credentials`,
    {
      headers: {
        Authorization: `Basic ${auth}`
      }
    }
  );

  return response.data.access_token;
}

app.post("/api/mpesa/stk", authRequired, async (req, res) => {
  try {
    const { phone, amount } = req.body;

    if (!phone || !amount) {
      return res.status(400).json({ error: "Phone and amount required" });
    }

    const token = await getMpesaAccessToken();

    const baseUrl =
      process.env.MPESA_ENV === "production"
        ? "https://api.safaricom.co.ke"
        : "https://sandbox.safaricom.co.ke";

    const timestamp = new Date()
      .toISOString()
      .replace(/[-:TZ.]/g, "")
      .slice(0, 14);

    const shortcode = process.env.MPESA_SHORTCODE;
    const passkey = process.env.MPESA_PASSKEY;

    const password = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString(
      "base64"
    );

    const payload = {
      BusinessShortCode: shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: "CustomerPayBillOnline",
      Amount: Number(amount),
      PartyA: phone,
      PartyB: shortcode,
      PhoneNumber: phone,
      CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: process.env.MPESA_ACCOUNT_REFERENCE,
      TransactionDesc: process.env.MPESA_TRANSACTION_DESC
    };

    const response = await axios.post(
      `${baseUrl}/mpesa/stkpush/v1/processrequest`,
      payload,
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    await db.query(
      `
      INSERT INTO payments 
      (user_id, checkout_request_id, merchant_request_id, phone, amount, status, raw_response)
      VALUES (?, ?, ?, ?, ?, 'pending', ?)
      `,
      [
        req.user.id,
        response.data.CheckoutRequestID,
        response.data.MerchantRequestID,
        phone,
        amount,
        JSON.stringify(response.data)
      ]
    );

    res.json({
      message: "STK push sent",
      data: response.data
    });
  } catch (error) {
    res.status(500).json({
      error: "M-Pesa request failed",
      details: error.response?.data || error.message
    });
  }
});

app.post("/api/mpesa/callback", async (req, res) => {
  try {
    const callback = req.body.Body?.stkCallback;
    const checkoutId = callback?.CheckoutRequestID;
    const resultCode = callback?.ResultCode;

    if (checkoutId && resultCode === 0) {
      const [payments] = await db.query(
        "SELECT * FROM payments WHERE checkout_request_id = ?",
        [checkoutId]
      );

      if (payments.length) {
        await db.query(
          "UPDATE payments SET status='success', raw_response=? WHERE checkout_request_id=?",
          [JSON.stringify(req.body), checkoutId]
        );

        await db.query("UPDATE users SET plan='premium' WHERE id=?", [
          payments[0].user_id
        ]);
      }
    }

    if (checkoutId && resultCode !== 0) {
      await db.query(
        "UPDATE payments SET status='failed', raw_response=? WHERE checkout_request_id=?",
        [JSON.stringify(req.body), checkoutId]
      );
    }

    res.json({ ResultCode: 0, ResultDesc: "Accepted" });
  } catch {
    res.json({ ResultCode: 0, ResultDesc: "Accepted" });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Server failed:", error);
    process.exit(1);
  });