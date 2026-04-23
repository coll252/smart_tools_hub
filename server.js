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
const { PDFDocument, rgb, StandardFonts } = require("pdf-lib");
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
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 30);

const uploadDir = path.join(__dirname, "uploads");
const publicDir = path.join(__dirname, "public");

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: false }));
app.use(cors());
app.use(express.json({ limit: "30mb" }));
app.use(express.urlencoded({ extended: true, limit: "30mb" }));
app.use(express.static(publicDir));

app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
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
    if (!header) return res.status(401).json({ error: "Login required" });

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

async function logToolUsage(req, toolName) {
  try {
    await db.query(
      "INSERT INTO tool_usage (user_id, tool_name, ip_address) VALUES (?, ?, ?)",
      [req.user?.id || null, toolName, req.ip]
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
      "SELECT id, uuid, name, email, role, plan FROM users WHERE id = ?",
      [result.insertId]
    );

    await db.query(
      "INSERT INTO notifications (user_id, title, message) VALUES (?, ?, ?)",
      [result.insertId, "Welcome", "Your SmartTools account was created successfully."]
    );

    res.json({ message: "Signup successful", token: signToken(rows[0]), user: rows[0] });
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
      "SELECT * FROM users WHERE email = ?",
      [email.trim().toLowerCase()]
    );

    if (!rows.length) return res.status(400).json({ error: "Invalid email or password" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(400).json({ error: "Invalid email or password" });

    const cleanUser = {
      id: user.id,
      uuid: user.uuid,
      name: user.name,
      email: user.email,
      role: user.role,
      plan: user.plan
    };

    res.json({ message: "Login successful", token: signToken(cleanUser), user: cleanUser });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/auth/me", authRequired, (req, res) => {
  res.json({ user: req.user });
});

/* USER DASHBOARD */

app.get("/api/dashboard", authRequired, async (req, res) => {
  const [[usage]] = await db.query(
    "SELECT COUNT(*) AS total FROM tool_usage WHERE user_id = ?",
    [req.user.id]
  );

  const [recentTools] = await db.query(
    "SELECT tool_name, created_at FROM tool_usage WHERE user_id = ? ORDER BY created_at DESC LIMIT 15",
    [req.user.id]
  );

  const [files] = await db.query(
    "SELECT tool_name, original_name, output_name, created_at FROM saved_files WHERE user_id = ? ORDER BY created_at DESC LIMIT 15",
    [req.user.id]
  );

  const [favorites] = await db.query(
    "SELECT tool_name, created_at FROM favorites WHERE user_id = ? ORDER BY created_at DESC",
    [req.user.id]
  );

  const [notifications] = await db.query(
    "SELECT id, title, message, is_read, created_at FROM notifications WHERE user_id = ? OR user_id IS NULL ORDER BY created_at DESC LIMIT 20",
    [req.user.id]
  );

  res.json({
    user: req.user,
    usageTotal: usage.total,
    recentTools,
    files,
    favorites,
    notifications
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

/* PDF TOOLS */

app.post("/api/tools/pdf-split", authOptional, upload.single("pdf"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "PDF required" });

    const start = Math.max(Number(req.body.start || 1), 1);
    const endInput = Number(req.body.end || start);

    const bytes = fs.readFileSync(req.file.path);
    const srcPdf = await PDFDocument.load(bytes);
    const totalPages = srcPdf.getPageCount();
    const end = Math.min(endInput, totalPages);

    const newPdf = await PDFDocument.create();
    const indices = [];

    for (let i = start - 1; i <= end - 1; i++) indices.push(i);

    const copied = await newPdf.copyPages(srcPdf, indices);
    copied.forEach(p => newPdf.addPage(p));

    const out = await newPdf.save();
    outputPath = path.join(uploadDir, `split-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, out);

    await logToolUsage(req, "pdf-splitter");
    await saveFileHistory(req, "pdf-splitter", req.file.originalname, "split.pdf");

    safeDelete(req.file.path);

    res.download(outputPath, "split.pdf", () => safeDelete(outputPath));
  } catch (error) {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "PDF split failed" });
  }
});

app.post("/api/tools/pdf-merge", authOptional, upload.array("pdfs", 10), async (req, res) => {
  let outputPath;
  try {
    if (!req.files || req.files.length < 2) {
      return res.status(400).json({ error: "Upload at least 2 PDFs" });
    }

    const mergedPdf = await PDFDocument.create();

    for (const file of req.files) {
      const pdfBytes = fs.readFileSync(file.path);
      const pdf = await PDFDocument.load(pdfBytes);
      const copiedPages = await mergedPdf.copyPages(pdf, pdf.getPageIndices());
      copiedPages.forEach(page => mergedPdf.addPage(page));
    }

    const mergedBytes = await mergedPdf.save();
    outputPath = path.join(uploadDir, `merged-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, mergedBytes);

    await logToolUsage(req, "pdf-merger");
    await saveFileHistory(req, "pdf-merger", "multiple PDFs", "merged.pdf");

    req.files.forEach(file => safeDelete(file.path));

    res.download(outputPath, "merged.pdf", () => safeDelete(outputPath));
  } catch {
    req.files?.forEach(file => safeDelete(file.path));
    safeDelete(outputPath);
    res.status(500).json({ error: "PDF merge failed" });
  }
});

app.post("/api/tools/pdf-watermark", authOptional, upload.single("pdf"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "PDF required" });

    const text = req.body.text || "SmartTools";
    const bytes = fs.readFileSync(req.file.path);
    const pdf = await PDFDocument.load(bytes);
    const font = await pdf.embedFont(StandardFonts.HelveticaBold);

    pdf.getPages().forEach(page => {
      const { width, height } = page.getSize();
      page.drawText(text, {
        x: width / 4,
        y: height / 2,
        size: 42,
        font,
        color: rgb(0.75, 0.75, 0.75),
        opacity: 0.35,
        rotate: { type: "degrees", angle: -30 }
      });
    });

    const out = await pdf.save();
    outputPath = path.join(uploadDir, `watermarked-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, out);

    await logToolUsage(req, "pdf-watermark");
    await saveFileHistory(req, "pdf-watermark", req.file.originalname, "watermarked.pdf");

    safeDelete(req.file.path);

    res.download(outputPath, "watermarked.pdf", () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "PDF watermark failed" });
  }
});

app.post("/api/tools/pdf-compress", authOptional, upload.single("pdf"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "PDF required" });

    const bytes = fs.readFileSync(req.file.path);
    const pdf = await PDFDocument.load(bytes);
    const out = await pdf.save({ useObjectStreams: true });

    outputPath = path.join(uploadDir, `compressed-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, out);

    await logToolUsage(req, "pdf-compressor");
    await saveFileHistory(req, "pdf-compressor", req.file.originalname, "compressed.pdf");

    safeDelete(req.file.path);

    res.download(outputPath, "compressed.pdf", () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "PDF compression failed" });
  }
});

app.post("/api/tools/image-to-pdf", authOptional, upload.array("images", 20), async (req, res) => {
  let outputPath;
  try {
    if (!req.files || !req.files.length) {
      return res.status(400).json({ error: "Images required" });
    }

    const pdf = await PDFDocument.create();

    for (const file of req.files) {
      const imageBytes = fs.readFileSync(file.path);
      const ext = file.originalname.toLowerCase();

      let img;
      if (ext.endsWith(".png")) img = await pdf.embedPng(imageBytes);
      else img = await pdf.embedJpg(await sharp(file.path).jpeg().toBuffer());

      const page = pdf.addPage([img.width, img.height]);
      page.drawImage(img, { x: 0, y: 0, width: img.width, height: img.height });
    }

    const out = await pdf.save();
    outputPath = path.join(uploadDir, `images-${Date.now()}.pdf`);
    fs.writeFileSync(outputPath, out);

    await logToolUsage(req, "image-to-pdf");
    await saveFileHistory(req, "image-to-pdf", "images", "images.pdf");

    req.files.forEach(file => safeDelete(file.path));

    res.download(outputPath, "images.pdf", () => safeDelete(outputPath));
  } catch {
    req.files?.forEach(file => safeDelete(file.path));
    safeDelete(outputPath);
    res.status(500).json({ error: "Image to PDF failed" });
  }
});

app.post("/api/tools/pdf-to-word", authOptional, upload.single("pdf"), async (req, res) => {
  safeDelete(req.file?.path);
  res.status(501).json({
    error: "PDF to Word needs a conversion engine/API such as CloudConvert, ConvertAPI, or LibreOffice server."
  });
});

app.post("/api/tools/word-to-pdf", authOptional, upload.single("word"), async (req, res) => {
  safeDelete(req.file?.path);
  res.status(501).json({
    error: "Word to PDF needs LibreOffice/CloudConvert/ConvertAPI. Endpoint is ready for integration."
  });
});

app.post("/api/tools/pdf-to-image", authOptional, upload.single("pdf"), async (req, res) => {
  safeDelete(req.file?.path);
  res.status(501).json({
    error: "PDF to Image needs Poppler/Ghostscript or an external API. Endpoint is ready."
  });
});

/* IMAGE TOOLS */

app.post("/api/tools/image-compress", authOptional, upload.single("image"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const quality = Math.min(Math.max(Number(req.body.quality || 65), 10), 95);
    outputPath = path.join(uploadDir, `compressed-${Date.now()}.jpg`);

    await sharp(req.file.path).rotate().jpeg({ quality }).toFile(outputPath);

    await logToolUsage(req, "image-compressor");
    await saveFileHistory(req, "image-compressor", req.file.originalname, "compressed-image.jpg");

    safeDelete(req.file.path);

    res.download(outputPath, "compressed-image.jpg", () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image compression failed" });
  }
});

app.post("/api/tools/image-resize", authOptional, upload.single("image"), async (req, res) => {
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

    await logToolUsage(req, "image-resizer");
    await saveFileHistory(req, "image-resizer", req.file.originalname, "resized-image.jpg");

    safeDelete(req.file.path);

    res.download(outputPath, "resized-image.jpg", () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image resize failed" });
  }
});

app.post("/api/tools/image-convert", authOptional, upload.single("image"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const format = ["png", "jpg", "jpeg", "webp"].includes(req.body.format)
      ? req.body.format
      : "png";

    const ext = format === "jpg" ? "jpeg" : format;
    outputPath = path.join(uploadDir, `converted-${Date.now()}.${format}`);

    await sharp(req.file.path).rotate().toFormat(ext).toFile(outputPath);

    await logToolUsage(req, "image-converter");
    await saveFileHistory(req, "image-converter", req.file.originalname, `converted.${format}`);

    safeDelete(req.file.path);

    res.download(outputPath, `converted.${format}`, () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image conversion failed" });
  }
});

app.post("/api/tools/image-crop", authOptional, upload.single("image"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const left = Number(req.body.left || 0);
    const top = Number(req.body.top || 0);
    const width = Number(req.body.width || 300);
    const height = Number(req.body.height || 300);

    outputPath = path.join(uploadDir, `cropped-${Date.now()}.png`);

    await sharp(req.file.path)
      .extract({ left, top, width, height })
      .png()
      .toFile(outputPath);

    await logToolUsage(req, "image-cropper");
    await saveFileHistory(req, "image-cropper", req.file.originalname, "cropped.png");

    safeDelete(req.file.path);

    res.download(outputPath, "cropped.png", () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image crop failed. Check crop dimensions." });
  }
});

app.post("/api/tools/image-watermark", authOptional, upload.single("image"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const text = req.body.text || "SmartTools";
    const svg = `
      <svg width="800" height="200">
        <text x="30" y="100" font-size="60" fill="white" opacity="0.7" font-family="Arial">${text}</text>
      </svg>
    `;

    outputPath = path.join(uploadDir, `watermarked-${Date.now()}.png`);

    await sharp(req.file.path)
      .rotate()
      .composite([{ input: Buffer.from(svg), gravity: "southeast" }])
      .png()
      .toFile(outputPath);

    await logToolUsage(req, "image-watermark");
    await saveFileHistory(req, "image-watermark", req.file.originalname, "watermarked.png");

    safeDelete(req.file.path);

    res.download(outputPath, "watermarked.png", () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image watermark failed" });
  }
});

app.post("/api/tools/image-effect", authOptional, upload.single("image"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const effect = req.body.effect || "blur";
    let pipeline = sharp(req.file.path).rotate();

    if (effect === "blur") pipeline = pipeline.blur(Number(req.body.amount || 5));
    if (effect === "sharpen") pipeline = pipeline.sharpen();

    outputPath = path.join(uploadDir, `effect-${Date.now()}.png`);

    await pipeline.png().toFile(outputPath);

    await logToolUsage(req, `image-${effect}`);
    await saveFileHistory(req, `image-${effect}`, req.file.originalname, "effect.png");

    safeDelete(req.file.path);

    res.download(outputPath, "effect.png", () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Image effect failed" });
  }
});

app.post("/api/tools/background-changer", authOptional, upload.single("image"), async (req, res) => {
  let outputPath;
  try {
    if (!req.file) return res.status(400).json({ error: "Image required" });

    const color = req.body.color || "#ffffff";
    const metadata = await sharp(req.file.path).metadata();

    outputPath = path.join(uploadDir, `background-${Date.now()}.png`);

    const bg = await sharp({
      create: {
        width: metadata.width,
        height: metadata.height,
        channels: 4,
        background: color
      }
    }).png().toBuffer();

    await sharp(bg)
      .composite([{ input: req.file.path }])
      .png()
      .toFile(outputPath);

    await logToolUsage(req, "background-changer");
    await saveFileHistory(req, "background-changer", req.file.originalname, "background-changed.png");

    safeDelete(req.file.path);

    res.download(outputPath, "background-changed.png", () => safeDelete(outputPath));
  } catch {
    safeDelete(req.file?.path);
    safeDelete(outputPath);
    res.status(500).json({ error: "Background change failed" });
  }
});

app.post("/api/tools/background-remover", authOptional, upload.single("image"), async (req, res) => {
  safeDelete(req.file?.path);
  res.status(501).json({
    error: "Background remover needs remove.bg, Clipdrop, PhotoRoom, or an AI model. Endpoint is ready for API integration."
  });
});

app.post("/api/tools/image-upscale", authOptional, upload.single("image"), async (req, res) => {
  safeDelete(req.file?.path);
  res.status(501).json({
    error: "AI upscaler needs an AI model/API. Endpoint is ready for integration."
  });
});

/* ARCHIVE TOOLS */

app.post("/api/tools/zip-extract", authOptional, upload.single("zip"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "ZIP required" });

    const zip = new AdmZip(req.file.path);
    const entries = zip.getEntries().map(e => ({
      name: e.entryName,
      size: e.header.size,
      isDirectory: e.isDirectory
    }));

    await logToolUsage(req, "zip-extractor");
    safeDelete(req.file.path);

    res.json({ entries });
  } catch {
    safeDelete(req.file?.path);
    res.status(500).json({ error: "ZIP extraction failed" });
  }
});

app.post("/api/tools/file-compress", authOptional, upload.array("files", 20), async (req, res) => {
  let outputPath;
  try {
    if (!req.files || !req.files.length) return res.status(400).json({ error: "Files required" });

    outputPath = path.join(uploadDir, `compressed-${Date.now()}.zip`);
    const output = fs.createWriteStream(outputPath);
    const archive = archiver("zip", { zlib: { level: 9 } });

    archive.pipe(output);

    req.files.forEach(file => {
      archive.file(file.path, { name: file.originalname });
    });

    await archive.finalize();

    output.on("close", async () => {
      await logToolUsage(req, "file-compressor");
      req.files.forEach(file => safeDelete(file.path));

      res.download(outputPath, "compressed-files.zip", () => safeDelete(outputPath));
    });
  } catch {
    req.files?.forEach(file => safeDelete(file.path));
    safeDelete(outputPath);
    res.status(500).json({ error: "File compression failed" });
  }
});

app.post("/api/tools/file-converter", authOptional, upload.single("file"), async (req, res) => {
  safeDelete(req.file?.path);
  res.status(501).json({
    error: "Universal file conversion needs CloudConvert/ConvertAPI. Endpoint is ready."
  });
});

/* UTILITY + DEV TOOLS */

app.post("/api/tools/qr", authOptional, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "Text required" });

  const qrImage = await QRCode.toDataURL(text, { width: 350, margin: 2 });

  await logToolUsage(req, "qr-generator");

  res.json({ qrImage });
});

app.post("/api/tools/password", authOptional, async (req, res) => {
  const length = Math.min(Math.max(Number(req.body.length || 16), 4), 64);
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=";

  let password = "";
  for (let i = 0; i < length; i++) password += chars[Math.floor(Math.random() * chars.length)];

  await logToolUsage(req, "password-generator");

  res.json({ password });
});

app.post("/api/tools/hash", authOptional, async (req, res) => {
  const text = req.body.text || "";
  const algorithm = req.body.algorithm || "sha256";

  if (!["md5", "sha1", "sha256", "sha512"].includes(algorithm)) {
    return res.status(400).json({ error: "Invalid algorithm" });
  }

  const hash = crypto.createHash(algorithm).update(text).digest("hex");

  await logToolUsage(req, "hash-generator");

  res.json({ hash });
});

app.post("/api/tools/api-tester", authOptional, async (req, res) => {
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

app.post("/api/feedback", authOptional, async (req, res) => {
  const { name, email, message } = req.body;

  if (!message) return res.status(400).json({ error: "Message required" });

  await db.query(
    "INSERT INTO feedback (user_id, name, email, message) VALUES (?, ?, ?, ?)",
    [req.user?.id || null, name || null, email || null, message]
  );

  res.json({ message: "Feedback sent successfully" });
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
