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
const { PDFDocument, rgb, StandardFonts, degrees } = require("pdf-lib");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const AdmZip = require("adm-zip");
const archiver = require("archiver");

const app = express();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const FREE_DAILY_LIMIT = Number(process.env.FREE_DAILY_LIMIT || 50);
const PREMIUM_DAILY_LIMIT = Number(process.env.PREMIUM_DAILY_LIMIT || 2000);
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 40);
const PREMIUM_AMOUNT = Number(process.env.PREMIUM_AMOUNT || 200);

const uploadDir = path.join(__dirname, "uploads");
const publicDir = path.join(__dirname, "public");

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors());
app.use(express.json({ limit: "40mb" }));
app.use(express.urlencoded({ extended: true, limit: "40mb" }));
app.use(express.static(publicDir));

app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 400,
  message: { error: "Too many requests. Try again later." }
}));

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 }
});

let db;

async function connectDB() {
  db = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT || 3306),
    waitForConnections: true,
    connectionLimit: 10,
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : undefined
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
      premium_until DATETIME NULL,
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
      file_size BIGINT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS saved_files (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      tool_name VARCHAR(100),
      original_name VARCHAR(255),
      output_name VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS favorites (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      tool_name VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      title VARCHAR(255),
      message TEXT,
      is_read BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS feedback (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      name VARCHAR(150),
      email VARCHAR(150),
      message TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

function safeDelete(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) fs.unlinkSync(filePath);
  } catch {}
}

function signToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, plan: user.plan },
    JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" }
  );
}

async function refreshPremiumStatus(userId) {
  const [rows] = await db.query("SELECT premium_until FROM users WHERE id=?", [userId]);
  if (!rows.length) return;

  if (rows[0].premium_until && new Date(rows[0].premium_until) < new Date()) {
    await db.query("UPDATE users SET plan='free', premium_until=NULL WHERE id=?", [userId]);
  }
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
    await refreshPremiumStatus(decoded.id);

    const [rows] = await db.query(
      "SELECT id, uuid, name, email, role, plan, premium_until, is_active FROM users WHERE id=?",
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
    if (!header) return res.status(401).json({ error: "Login required" });

    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    await refreshPremiumStatus(decoded.id);

    const [rows] = await db.query(
      "SELECT id, uuid, name, email, role, plan, premium_until, is_active FROM users WHERE id=?",
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
    const limit = req.user?.plan === "premium" ? PREMIUM_DAILY_LIMIT : FREE_DAILY_LIMIT;

    let rows;

    if (userId) {
      [rows] = await db.query(
        "SELECT COUNT(*) AS total FROM tool_usage WHERE user_id=? AND DATE(created_at)=CURDATE()",
        [userId]
      );
    } else {
      [rows] = await db.query(
        "SELECT COUNT(*) AS total FROM tool_usage WHERE ip_address=? AND DATE(created_at)=CURDATE()",
        [ip]
      );
    }

    if (rows[0].total >= limit) {
      return res.status(429).json({ error: "Daily limit reached. Upgrade to Premium." });
    }

    next();
  } catch {
    res.status(500).json({ error: "Limit check failed" });
  }
}

function requirePremium(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  if (req.user.plan !== "premium") return res.status(403).json({ error: "Premium required" });
  next();
}

async function logToolUsage(req, toolName, fileSize = 0) {
  try {
    await db.query(
      "INSERT INTO tool_usage (user_id, tool_name, ip_address, file_size) VALUES (?, ?, ?, ?)",
      [req.user?.id || null, toolName, req.ip, fileSize]
    );
  } catch {}
}

async function saveFileHistory(req, toolName, originalName, outputName) {
  try {
    await db.query(
      "INSERT INTO saved_files (user_id, tool_name, original_name, output_name) VALUES (?, ?, ?, ?)",
      [req.user?.id || null, toolName, originalName || null, outputName || null]
    );
  } catch {}
}

async function notifyUser(userId, title, message) {
  try {
    await db.query(
      "INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)",
      [userId || null, title, message]
    );
  } catch {}
}

function downloadAndClean(res, filePath, fileName) {
  res.download(filePath, fileName, () => safeDelete(filePath));
}

/* BASIC */

app.get("/", (req, res) => {
  const file = path.join(publicDir, "index.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  res.status(500).send("index.html not found inside public folder");
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", app: "SmartTools Hub" });
});

app.get("/api/check-file", (req, res) => {
  const indexPath = path.join(publicDir, "index.html");
  res.json({ publicDir, indexPath, exists: fs.existsSync(indexPath) });
});

/* AUTH */

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Name, email and password required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be 6+ characters" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      "INSERT INTO users (uuid, name, email, password) VALUES (?, ?, ?, ?)",
      [uuidv4(), name.trim(), email.trim().toLowerCase(), hashedPassword]
    );

    const [rows] = await db.query(
      "SELECT id, uuid, name, email, role, plan, premium_until FROM users WHERE id=?",
      [result.insertId]
    );

    await notifyUser(result.insertId, "Welcome", "Your SmartTools account was created successfully.");

    res.json({
      message: "Signup successful",
      token: signToken(rows[0]),
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

    const [rows] = await db.query(
      "SELECT * FROM users WHERE email=?",
      [email.trim().toLowerCase()]
    );

    if (!rows.length) return res.status(400).json({ error: "Invalid email or password" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(400).json({ error: "Invalid email or password" });

    await refreshPremiumStatus(user.id);

    const [cleanRows] = await db.query(
      "SELECT id, uuid, name, email, role, plan, premium_until FROM users WHERE id=?",
      [user.id]
    );

    res.json({
      message: "Login successful",
      token: signToken(cleanRows[0]),
      user: cleanRows[0]
    });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ user: req.user });
});

/* DASHBOARD */

app.get("/api/dashboard", authRequired, async (req, res) => {
  const [[usage]] = await db.query(
    "SELECT COUNT(*) AS total FROM tool_usage WHERE user_id=?",
    [req.user.id]
  );

  const [[today]] = await db.query(
    "SELECT COUNT(*) AS total FROM tool_usage WHERE user_id=? AND DATE(created_at)=CURDATE()",
    [req.user.id]
  );

  const [recentTools] = await db.query(
    "SELECT tool_name, created_at FROM tool_usage WHERE user_id=? ORDER BY created_at DESC LIMIT 25",
    [req.user.id]
  );

  const [popularTools] = await db.query(`
    SELECT tool_name, COUNT(*) AS total
    FROM tool_usage
    GROUP BY tool_name
    ORDER BY total DESC
    LIMIT 15
  `);

  const [files] = await db.query(
    "SELECT tool_name, original_name, output_name, created_at FROM saved_files WHERE user_id=? ORDER BY created_at DESC LIMIT 30",
    [req.user.id]
  );

  const [favorites] = await db.query(
    "SELECT tool_name, created_at FROM favorites WHERE user_id=? ORDER BY created_at DESC",
    [req.user.id]
  );

  const [notifications] = await db.query(
    "SELECT id, title, message, is_read, created_at FROM notifications WHERE user_id=? OR user_id IS NULL ORDER BY created_at DESC LIMIT 30",
    [req.user.id]
  );

  res.json({
    user: req.user,
    usageTotal: usage.total,
    todayUsage: today.total,
    dailyLimit: req.user.plan === "premium" ? PREMIUM_DAILY_LIMIT : FREE_DAILY_LIMIT,
    recentTools,
    popularTools,
    files,
    favorites,
    notifications,
    recommendations: recentTools.slice(0, 6).map(t => {
      if (t.tool_name.includes("pdf")) return "Try PDF Watermark, PDF Page Numbers, or PDF Compressor.";
      if (t.tool_name.includes("image")) return "Try Studio Effects, Image Converter, or Background Remover.";
      return "Try Hash Generator, API Tester, or QR Generator.";
    })
  });
});

app.post("/api/favorites", authRequired, async (req, res) => {
  const { toolName } = req.body;
  if (!toolName) return res.status(400).json({ error: "toolName required" });

  await db.query(
    "INSERT INTO favorites (user_id, tool_name) VALUES (?, ?)",
    [req.user.id, toolName]
  );

  res.json({ message: "Added to favorites" });
});

app.post("/api/notifications/read", authRequired, async (req, res) => {
  await db.query("UPDATE notifications SET is_read=true WHERE user_id=?", [req.user.id]);
  res.json({ message: "Notifications marked as read" });
});

/* MONETIZATION */

app.get("/api/pricing", (req, res) => {
  res.json({
    plans: [
      { name: "Free", price: 0, features: ["Ads shown", `${FREE_DAILY_LIMIT} uses/day`, "Basic tools"] },
      { name: "Premium", price: PREMIUM_AMOUNT, currency: "KES", features: ["No ads", `${PREMIUM_DAILY_LIMIT} uses/day`, "Premium tools"] }
    ]
  });
});

app.post("/api/subscription/manual-upgrade", authRequired, async (req, res) => {
  if (process.env.ALLOW_MANUAL_PREMIUM !== "true") {
    return res.status(403).json({ error: "Manual upgrade disabled" });
  }

  await db.query(
    "UPDATE users SET plan='premium', premium_until=DATE_ADD(NOW(), INTERVAL 30 DAY) WHERE id=?",
    [req.user.id]
  );

  await notifyUser(req.user.id, "Premium Activated", "Your premium subscription is active for 30 days.");
  res.json({ message: "Premium activated for testing" });
});

async function getMpesaAccessToken() {
  const auth = Buffer.from(
    `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
  ).toString("base64");

  const baseUrl = process.env.MPESA_ENV === "production"
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";

  const response = await axios.get(
    `${baseUrl}/oauth/v1/generate?grant_type=client_credentials`,
    { headers: { Authorization: `Basic ${auth}` } }
  );

  return response.data.access_token;
}

app.post("/api/mpesa/stk", authRequired, async (req, res) => {
  try {
    const { phone, amount } = req.body;
    const finalAmount = Number(amount || PREMIUM_AMOUNT);

    if (!phone) return res.status(400).json({ error: "Phone required" });

    const token = await getMpesaAccessToken();

    const baseUrl = process.env.MPESA_ENV === "production"
      ? "https://api.safaricom.co.ke"
      : "https://sandbox.safaricom.co.ke";

    const timestamp = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
    const shortcode = process.env.MPESA_SHORTCODE;
    const passkey = process.env.MPESA_PASSKEY;
    const password = Buffer.from(`${shortcode}${passkey}${timestamp}`).toString("base64");

    const payload = {
      BusinessShortCode: shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: "CustomerPayBillOnline",
      Amount: finalAmount,
      PartyA: phone,
      PartyB: shortcode,
      PhoneNumber: phone,
      CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: process.env.MPESA_ACCOUNT_REFERENCE || "SMARTTOOLS",
      TransactionDesc: process.env.MPESA_TRANSACTION_DESC || "SmartTools Premium"
    };

    const response = await axios.post(
      `${baseUrl}/mpesa/stkpush/v1/processrequest`,
      payload,
      { headers: { Authorization: `Bearer ${token}` } }
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
        finalAmount,
        JSON.stringify(response.data)
      ]
    );

    res.json({ message: "STK push sent. Complete payment on your phone.", data: response.data });
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
        "SELECT * FROM payments WHERE checkout_request_id=?",
        [checkoutId]
      );

      if (payments.length) {
        await db.query(
          "UPDATE payments SET status='success', raw_response=? WHERE checkout_request_id=?",
          [JSON.stringify(req.body), checkoutId]
        );

        await db.query(
          "UPDATE users SET plan='premium', premium_until=DATE_ADD(NOW(), INTERVAL 30 DAY) WHERE id=?",
          [payments[0].user_id]
        );

        await notifyUser(payments[0].user_id, "Premium Activated", "Payment received. Premium is active for 30 days.");
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

/* PDF TOOLS */

app.post("/api/tools/pdf-merge", authOptional, checkToolLimit, upload.array("pdfs", 10), async (req, res) => {
  let outputPath;

  try {
    if (!req.files || req.files.length < 2) return res.status(400).json({ error: "Upload at least 2 PDFs" });

    const mergedPdf = await PDFDocument.create();

    for (const file of req.files) {
      const pdfBytes = fs.readFileSync(file.path);
      const pdf = await PDFDocument.load(pdfBytes);
      const copiedPages = await mergedPdf.copyPages(pdf, pdf.getPageIndices());
      copiedPages.forEach(page => mergedPdf.addPage(page));
    }

    outputPath = path.join(uploadDir, `merged-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, await mergedPdf.save());

    await logToolUsage(req, "pdf-merger");
    await saveFileHistory(req, "pdf-merger", "multiple PDFs", "merged.pdf");

    req.files.forEach(f => safeDelete(f.path));
    downloadAndClean(res, outputPath, "merged.pdf");
  } catch {
    req.files?.forEach(f => safeDelete(f.path));
    safeDelete(outputPath);
    res.status(500).json({ error: "PDF merge failed" });
  }
});

app.post("/api/tools/pdf-split", authOptional, checkToolLimit, upload.single("pdf"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "PDF required" });

    const start = Math.max(Number(req.body.start || 1), 1);
    const endInput = Number(req.body.end || start);

    const srcPdf = await PDFDocument.load(fs.readFileSync(req.file.path));
    const totalPages = srcPdf.getPageCount();
    const end = Math.min(endInput, totalPages);

    const newPdf = await PDFDocument.create();
    const indices = [];

    for (let i = start - 1; i <= end - 1; i++) indices.push(i);

    const copied = await newPdf.copyPages(srcPdf, indices);
    copied.forEach(p => newPdf.addPage(p));

    outputPath = path.join(uploadDir, `split-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, await newPdf.save());

    await logToolUsage(req, "pdf-splitter");
    await saveFileHistory(req, "pdf-splitter", req.file.originalname, "split.pdf");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "split.pdf");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "PDF split failed" });
  }
});

app.post("/api/tools/pdf-watermark", authOptional, checkToolLimit, upload.single("pdf"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "PDF required" });

    const text = req.body.text || "SmartTools";
    const pdf = await PDFDocument.load(fs.readFileSync(req.file.path));
    const font = await pdf.embedFont(StandardFonts.HelveticaBold);

    pdf.getPages().forEach(page => {
      const { width, height } = page.getSize();
      page.drawText(text, {
        x: width / 5,
        y: height / 2,
        size: 42,
        font,
        color: rgb(0.75, 0.75, 0.75),
        opacity: 0.35,
        rotate: degrees(-30)
      });
    });

    outputPath = path.join(uploadDir, `watermarked-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, await pdf.save());

    await logToolUsage(req, "pdf-watermark");
    await saveFileHistory(req, "pdf-watermark", req.file.originalname, "watermarked.pdf");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "watermarked.pdf");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "PDF watermark failed" });
  }
});

app.post("/api/tools/pdf-compress", authOptional, checkToolLimit, upload.single("pdf"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "PDF required" });

    const pdf = await PDFDocument.load(fs.readFileSync(req.file.path));
    outputPath = path.join(uploadDir, `compressed-${Date.now()}.pdf`);

    fs.writeFileSync(outputPath, await pdf.save({ useObjectStreams: true }));

    await logToolUsage(req, "pdf-compressor");
    await saveFileHistory(req, "pdf-compressor", req.file.originalname, "compressed.pdf");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "compressed.pdf");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "PDF compression failed" });
  }
});

app.post("/api/tools/pdf-page-numbers", authOptional, checkToolLimit, upload.single("pdf"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "PDF required" });

    const pdf = await PDFDocument.load(fs.readFileSync(req.file.path));
    const font = await pdf.embedFont(StandardFonts.Helvetica);

    pdf.getPages().forEach((page, index) => {
      const { width } = page.getSize();
      page.drawText(`${index + 1}`, {
        x: width / 2,
        y: 25,
        size: 12,
        font,
        color: rgb(0, 0, 0)
      });
    });

    outputPath = path.join(uploadDir, `numbered-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, await pdf.save());

    await logToolUsage(req, "pdf-page-numbers");
    await saveFileHistory(req, "pdf-page-numbers", req.file.originalname, "numbered.pdf");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "numbered.pdf");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Adding page numbers failed" });
  }
});

app.post("/api/tools/pdf-info", authOptional, checkToolLimit, upload.single("pdf"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "PDF required" });

    const pdf = await PDFDocument.load(fs.readFileSync(req.file.path));

    await logToolUsage(req, "pdf-info");

    const info = {
      pages: pdf.getPageCount(),
      title: pdf.getTitle() || null,
      author: pdf.getAuthor() || null,
      subject: pdf.getSubject() || null,
      producer: pdf.getProducer() || null,
      creator: pdf.getCreator() || null
    };

    safeDelete(req.file.path);
    res.json(info);
  } catch {
    safeDelete(req.file?.path);
    res.status(500).json({ error: "PDF info failed" });
  }
});

app.post("/api/tools/image-to-pdf", authOptional, checkToolLimit, upload.array("images", 20), async (req, res) => {
  let outputPath;

  try {
    if (!req.files || !req.files.length) return res.status(400).json({ error: "Images required" });

    const pdf = await PDFDocument.create();

    for (const file of req.files) {
      const jpgBuffer = await sharp(file.path).rotate().jpeg().toBuffer();
      const img = await pdf.embedJpg(jpgBuffer);
      const page = pdf.addPage([img.width, img.height]);
      page.drawImage(img, { x: 0, y: 0, width: img.width, height: img.height });
    }

    outputPath = path.join(uploadDir, `images-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, await pdf.save());

    await logToolUsage(req, "image-to-pdf");
    await saveFileHistory(req, "image-to-pdf", "images", "images.pdf");

    req.files.forEach(f => safeDelete(f.path));
    downloadAndClean(res, outputPath, "images.pdf");
  } catch {
    req.files?.forEach(f => safeDelete(f.path));
    safeDelete(outputPath);
    res.status(500).json({ error: "Image to PDF failed" });
  }
});

/* IMAGE TOOLS */

app.post("/api/tools/image-compress", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const quality = Math.min(Math.max(Number(req.body.quality || 65), 10), 95);
    outputPath = path.join(uploadDir, `compressed-${Date.now()}.jpg`);

    await sharp(req.file.path).rotate().jpeg({ quality }).toFile(outputPath);

    await logToolUsage(req, "image-compressor", req.file.size);
    await saveFileHistory(req, "image-compressor", req.file.originalname, "compressed-image.jpg");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "compressed-image.jpg");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image compression failed" });
  }
});

app.post("/api/tools/image-resize", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const width = Math.min(Math.max(Number(req.body.width || 800), 50), 5000);
    const height = Math.min(Math.max(Number(req.body.height || 800), 50), 5000);

    outputPath = path.join(uploadDir, `resized-${Date.now()}.jpg`);

    await sharp(req.file.path)
      .rotate()
      .resize(width, height, { fit: "inside" })
      .jpeg({ quality: 85 })
      .toFile(outputPath);

    await logToolUsage(req, "image-resizer", req.file.size);
    await saveFileHistory(req, "image-resizer", req.file.originalname, "resized-image.jpg");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "resized-image.jpg");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image resize failed" });
  }
});

app.post("/api/tools/image-convert", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const format = ["png", "jpg", "jpeg", "webp"].includes(req.body.format) ? req.body.format : "png";
    const sharpFormat = format === "jpg" ? "jpeg" : format;

    outputPath = path.join(uploadDir, `converted-${Date.now()}.${format}`);

    await sharp(req.file.path).rotate().toFormat(sharpFormat).toFile(outputPath);

    await logToolUsage(req, "image-converter", req.file.size);
    await saveFileHistory(req, "image-converter", req.file.originalname, `converted.${format}`);

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, `converted.${format}`);
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image conversion failed" });
  }
});

app.post("/api/tools/image-crop", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const left = Number(req.body.left || 0);
    const top = Number(req.body.top || 0);
    const width = Number(req.body.width || 300);
    const height = Number(req.body.height || 300);

    outputPath = path.join(uploadDir, `cropped-${Date.now()}.png`);

    await sharp(req.file.path)
      .rotate()
      .extract({ left, top, width, height })
      .png()
      .toFile(outputPath);

    await logToolUsage(req, "image-cropper", req.file.size);
    await saveFileHistory(req, "image-cropper", req.file.originalname, "cropped.png");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "cropped.png");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image crop failed. Check crop dimensions." });
  }
});

app.post("/api/tools/image-watermark", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const text = (req.body.text || "SmartTools").replace(/[<>&]/g, "");
    const svg = `
      <svg width="1200" height="260">
        <text x="30" y="130" font-size="76" fill="white" opacity="0.75" font-family="Arial">${text}</text>
      </svg>
    `;

    outputPath = path.join(uploadDir, `watermarked-${Date.now()}.png`);

    await sharp(req.file.path)
      .rotate()
      .composite([{ input: Buffer.from(svg), gravity: "southeast" }])
      .png()
      .toFile(outputPath);

    await logToolUsage(req, "image-watermark", req.file.size);
    await saveFileHistory(req, "image-watermark", req.file.originalname, "watermarked.png");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "watermarked.png");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image watermark failed" });
  }
});

function applyStudioEffect(pipeline, effect) {
  switch (effect) {
    case "blur": return pipeline.blur(6);
    case "heavy-blur": return pipeline.blur(18);
    case "sharpen": return pipeline.sharpen();
    case "grayscale": return pipeline.grayscale();
    case "sepia": return pipeline.tint({ r: 112, g: 66, b: 20 }).modulate({ saturation: 0.8 });
    case "vintage": return pipeline.modulate({ brightness: 0.95, saturation: 0.6 }).tint({ r: 190, g: 150, b: 95 });
    case "warm": return pipeline.tint({ r: 255, g: 210, b: 170 }).modulate({ brightness: 1.05, saturation: 1.15 });
    case "cool": return pipeline.tint({ r: 170, g: 210, b: 255 }).modulate({ brightness: 1.02, saturation: 1.1 });
    case "bright": return pipeline.modulate({ brightness: 1.35 });
    case "dark": return pipeline.modulate({ brightness: 0.65 });
    case "high-contrast": return pipeline.linear(1.45, -20);
    case "low-contrast": return pipeline.linear(0.75, 20);
    case "saturate": return pipeline.modulate({ saturation: 1.8 });
    case "desaturate": return pipeline.modulate({ saturation: 0.35 });
    case "negative": return pipeline.negate();
    case "normalize": return pipeline.normalize();
    case "flip": return pipeline.flip();
    case "flop": return pipeline.flop();
    case "rotate-90": return pipeline.rotate(90);
    case "rotate-180": return pipeline.rotate(180);
    case "rotate-270": return pipeline.rotate(270);
    case "soft": return pipeline.blur(1.2).modulate({ brightness: 1.08, saturation: 0.95 });
    case "dramatic": return pipeline.modulate({ brightness: 0.9, saturation: 1.5 }).linear(1.35, -15);
    case "cinematic": return pipeline.modulate({ brightness: 0.9, saturation: 0.85 }).tint({ r: 160, g: 190, b: 210 });
    case "golden": return pipeline.tint({ r: 255, g: 205, b: 90 }).modulate({ saturation: 1.25 });
    case "rose": return pipeline.tint({ r: 255, g: 185, b: 205 }).modulate({ saturation: 1.2 });
    case "emerald": return pipeline.tint({ r: 120, g: 255, b: 190 }).modulate({ saturation: 1.1 });
    case "blueprint": return pipeline.grayscale().tint({ r: 50, g: 120, b: 255 });
    case "noir": return pipeline.grayscale().linear(1.45, -30);
    case "matte": return pipeline.modulate({ brightness: 1.06, saturation: 0.75 }).linear(0.88, 18);
    case "clean": return pipeline.normalize().sharpen().modulate({ brightness: 1.08, saturation: 1.08 });
    case "portrait-pop": return pipeline.modulate({ brightness: 1.08, saturation: 1.3 }).sharpen();
    case "food-pop": return pipeline.modulate({ brightness: 1.12, saturation: 1.55 }).sharpen();
    case "landscape-pop": return pipeline.modulate({ brightness: 1.05, saturation: 1.45 }).linear(1.15, -5);
    case "document-clean": return pipeline.grayscale().normalize().sharpen().linear(1.35, -15);
    case "washed": return pipeline.modulate({ brightness: 1.25, saturation: 0.45 }).linear(0.8, 35);
    case "deep-shadow": return pipeline.modulate({ brightness: 0.75, saturation: 1.15 }).linear(1.3, -25);
    case "neon": return pipeline.modulate({ brightness: 1.1, saturation: 2.4 }).linear(1.35, -25);
    case "dream": return pipeline.blur(1.5).modulate({ brightness: 1.2, saturation: 1.35 });
    case "web-optimized": return pipeline.resize({ width: 1200, withoutEnlargement: true }).jpeg({ quality: 78 });
    default: return pipeline;
  }
}

app.post("/api/tools/image-effect", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const effect = req.body.effect || "clean";
    let pipeline = sharp(req.file.path).rotate();

    pipeline = applyStudioEffect(pipeline, effect);

    outputPath = path.join(uploadDir, `effect-${Date.now()}.jpg`);
    await pipeline.jpeg({ quality: 90 }).toFile(outputPath);

    await logToolUsage(req, `image-${effect}`, req.file.size);
    await saveFileHistory(req, `image-${effect}`, req.file.originalname, "effect.jpg");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "effect.jpg");
  } catch (error) {
    console.error(error);
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image effect failed" });
  }
});

app.post("/api/tools/image-adjust", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const brightness = Number(req.body.brightness || 1);
    const saturation = Number(req.body.saturation || 1);
    const hue = Number(req.body.hue || 0);
    const contrast = Number(req.body.contrast || 1);

    outputPath = path.join(uploadDir, `adjusted-${Date.now()}.jpg`);

    await sharp(req.file.path)
      .rotate()
      .modulate({ brightness, saturation, hue })
      .linear(contrast, 0)
      .jpeg({ quality: 90 })
      .toFile(outputPath);

    await logToolUsage(req, "image-custom-adjust", req.file.size);
    await saveFileHistory(req, "image-custom-adjust", req.file.originalname, "adjusted.jpg");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "adjusted.jpg");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image adjustment failed" });
  }
});

app.post("/api/tools/background-remove-color", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const color = req.body.color || "#ffffff";
    const threshold = Math.min(Math.max(Number(req.body.threshold || 40), 1), 255);

    const hex = color.replace("#", "");
    const target = {
      r: parseInt(hex.slice(0, 2), 16),
      g: parseInt(hex.slice(2, 4), 16),
      b: parseInt(hex.slice(4, 6), 16)
    };

    const img = sharp(req.file.path).rotate().ensureAlpha();
    const { data, info } = await img.raw().toBuffer({ resolveWithObject: true });

    for (let i = 0; i < data.length; i += 4) {
      const dr = Math.abs(data[i] - target.r);
      const dg = Math.abs(data[i + 1] - target.g);
      const db = Math.abs(data[i + 2] - target.b);

      if (dr + dg + db < threshold * 3) data[i + 3] = 0;
    }

    outputPath = path.join(uploadDir, `bg-removed-${Date.now()}.png`);

    await sharp(data, { raw: { width: info.width, height: info.height, channels: 4 } })
      .png()
      .toFile(outputPath);

    await logToolUsage(req, "background-remove-color", req.file.size);
    await saveFileHistory(req, "background-remove-color", req.file.originalname, "background-removed.png");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "background-removed.png");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Background removal failed. Use images with solid backgrounds." });
  }
});

app.post("/api/tools/background-changer", authOptional, checkToolLimit, upload.single("image"), async (req, res) => {
  let outputPath;

  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const color = req.body.color || "#ffffff";
    const metadata = await sharp(req.file.path).metadata();

    const bg = await sharp({
      create: {
        width: metadata.width,
        height: metadata.height,
        channels: 4,
        background: color
      }
    }).png().toBuffer();

    outputPath = path.join(uploadDir, `background-${Date.now()}.png`);

    await sharp(bg).composite([{ input: req.file.path }]).png().toFile(outputPath);

    await logToolUsage(req, "background-changer", req.file.size);
    await saveFileHistory(req, "background-changer", req.file.originalname, "background-changed.png");

    safeDelete(req.file.path);
    downloadAndClean(res, outputPath, "background-changed.png");
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Background change failed" });
  }
});

/* ARCHIVE */

app.post("/api/tools/zip-extract", authOptional, checkToolLimit, upload.single("zip"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "ZIP required" });

    const zip = new AdmZip(req.file.path);
    const entries = zip.getEntries().map(e => ({
      name: e.entryName,
      size: e.header.size,
      isDirectory: e.isDirectory
    }));

    await logToolUsage(req, "zip-extractor", req.file.size);
    safeDelete(req.file.path);

    res.json({ entries });
  } catch {
    safeDelete(req.file?.path);
    res.status(500).json({ error: "ZIP extraction failed" });
  }
});

app.post("/api/tools/file-compress", authOptional, checkToolLimit, upload.array("files", 30), async (req, res) => {
  let outputPath;

  try {
    if (!req.files || !req.files.length) return res.status(400).json({ error: "Files required" });

    outputPath = path.join(uploadDir, `compressed-${Date.now()}.zip`);
    const output = fs.createWriteStream(outputPath);
    const archive = archiver("zip", { zlib: { level: 9 } });

    archive.pipe(output);

    req.files.forEach(file => archive.file(file.path, { name: file.originalname }));

    output.on("close", async () => {
      await logToolUsage(req, "file-compressor");
      await saveFileHistory(req, "file-compressor", "multiple files", "compressed-files.zip");
      req.files.forEach(file => safeDelete(file.path));
      downloadAndClean(res, outputPath, "compressed-files.zip");
    });

    await archive.finalize();
  } catch {
    req.files?.forEach(file => safeDelete(file.path));
    safeDelete(outputPath);
    res.status(500).json({ error: "File compression failed" });
  }
});

/* UTILITY */

app.post("/api/tools/password", authOptional, checkToolLimit, async (req, res) => {
  const length = Math.min(Math.max(Number(req.body.length || 16), 4), 128);
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=";

  let password = "";
  for (let i = 0; i < length; i++) password += chars[Math.floor(Math.random() * chars.length)];

  await logToolUsage(req, "password-generator");
  res.json({ password });
});

app.post("/api/tools/qr", authOptional, checkToolLimit, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "Text required" });

  const qrImage = await QRCode.toDataURL(text, { width: 350, margin: 2 });

  await logToolUsage(req, "qr-generator");
  res.json({ qrImage });
});

app.post("/api/tools/hash", authOptional, checkToolLimit, async (req, res) => {
  const text = req.body.text || "";
  const algorithm = req.body.algorithm || "sha256";

  if (!["md5", "sha1", "sha256", "sha512"].includes(algorithm)) {
    return res.status(400).json({ error: "Invalid algorithm" });
  }

  const hash = crypto.createHash(algorithm).update(text).digest("hex");

  await logToolUsage(req, "hash-generator");
  res.json({ hash });
});

app.post("/api/tools/text-stats", authOptional, checkToolLimit, async (req, res) => {
  const text = req.body.text || "";

  await logToolUsage(req, "text-stats");

  const words = text.trim() ? text.trim().split(/\s+/).length : 0;

  res.json({
    words,
    characters: text.length,
    charactersNoSpaces: text.replace(/\s/g, "").length,
    sentences: text.split(/[.!?]+/).filter(s => s.trim()).length,
    paragraphs: text.split(/\n+/).filter(p => p.trim()).length,
    readingTime: Math.ceil(words / 200)
  });
});

app.post("/api/tools/case-converter", authOptional, checkToolLimit, async (req, res) => {
  const text = req.body.text || "";
  const mode = req.body.mode || "upper";
  let output = text;

  if (mode === "upper") output = text.toUpperCase();
  if (mode === "lower") output = text.toLowerCase();
  if (mode === "title") output = text.toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
  if (mode === "sentence") output = text.toLowerCase().replace(/(^\s*\w|[.!?]\s*\w)/g, c => c.toUpperCase());
  if (mode === "reverse") output = text.split("").reverse().join("");
  if (mode === "slug") output = text.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  await logToolUsage(req, "case-converter");
  res.json({ output });
});

app.post("/api/tools/api-tester", authOptional, requirePremium, async (req, res) => {
  try {
    const { method, url, body, headers } = req.body;
    if (!url) return res.status(400).json({ error: "URL required" });

    const response = await axios({
      method: method || "GET",
      url,
      data: body || undefined,
      headers: headers || {},
      timeout: 15000
    });

    await logToolUsage(req, "api-tester");

    res.json({
      status: response.status,
      headers: response.headers,
      data: response.data
    });
  } catch (error) {
    res.status(500).json({
      error: "API request failed",
      details: error.response?.data || error.message
    });
  }
});

/* FEEDBACK */

app.post("/api/feedback", authOptional, async (req, res) => {
  const { name, email, message } = req.body;

  if (!message) return res.status(400).json({ error: "Message required" });

  await db.query(
    "INSERT INTO feedback (user_id, name, email, message) VALUES (?, ?, ?, ?)",
    [req.user?.id || null, name || null, email || null, message]
  );

  res.json({ message: "Feedback sent successfully" });
});

/* ADMIN */

app.get("/api/admin/stats", authRequired, async (req, res) => {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const [[users]] = await db.query("SELECT COUNT(*) AS total FROM users");
  const [[premium]] = await db.query("SELECT COUNT(*) AS total FROM users WHERE plan='premium'");
  const [[usage]] = await db.query("SELECT COUNT(*) AS total FROM tool_usage");
  const [[payments]] = await db.query("SELECT COUNT(*) AS total FROM payments WHERE status='success'");

  const [popularTools] = await db.query(`
    SELECT tool_name, COUNT(*) AS total
    FROM tool_usage
    GROUP BY tool_name
    ORDER BY total DESC
    LIMIT 20
  `);

  res.json({
    users: users.total,
    premiumUsers: premium.total,
    toolUsage: usage.total,
    successfulPayments: payments.total,
    popularTools
  });
});

app.use("/api", (req, res) => {
  res.status(404).json({ error: "API route not found" });
});

app.get("*", (req, res) => {
  const file = path.join(publicDir, "index.html");
  if (fs.existsSync(file)) return res.sendFile(file);
  res.status(404).send("index.html missing inside public folder");
});

connectDB()
  .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
  .catch(error => {
    console.error("Server failed:", error);
    process.exit(1);
  });
