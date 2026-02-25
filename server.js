require("dotenv").config();
const express = require("express");
const multer = require("multer");
const pdfParse = require("pdf-parse");
const XLSX = require("xlsx");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 8080;
const SITE_PASSWORD = process.env.SITE_PASSWORD || "qaws";
const ALLOWED_IPS = (process.env.ALLOWED_IPS || "").split(",").map((ip) => ip.trim()).filter(Boolean);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
});

// Parse JSON/URL-encoded bodies for login
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Trust proxy headers (Railway/reverse proxies set X-Forwarded-For)
app.set("trust proxy", true);

// IP whitelist middleware
app.use((req, res, next) => {
  if (ALLOWED_IPS.length === 0) return next(); // no restriction if empty
  const clientIp = req.ip?.replace(/^::ffff:/, "") || "";
  if (ALLOWED_IPS.includes(clientIp) || clientIp === "127.0.0.1" || clientIp === "::1") {
    return next();
  }
  console.log(`Blocked IP: ${clientIp}`);
  res.status(403).send("Access denied");
});

// Session-like auth via a cookie
const COOKIE_NAME = "muai_auth";
const COOKIE_VALUE = Buffer.from(SITE_PASSWORD).toString("base64");

function isAuthed(req) {
  return req.cookies?.[COOKIE_NAME] === COOKIE_VALUE;
}

// Simple cookie parser (avoid extra dependency)
app.use((req, res, next) => {
  req.cookies = {};
  const header = req.headers.cookie || "";
  header.split(";").forEach((c) => {
    const [k, ...v] = c.split("=");
    if (k) req.cookies[k.trim()] = v.join("=").trim();
  });
  next();
});

// Login endpoint
app.post("/api/login", (req, res) => {
  if (req.body.password === SITE_PASSWORD) {
    res.cookie(COOKIE_NAME, COOKIE_VALUE, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000, sameSite: "lax" });
    return res.json({ ok: true });
  }
  res.status(401).json({ error: "Wrong password" });
});

// Auth check endpoint
app.get("/api/auth-check", (req, res) => {
  res.json({ authed: isAuthed(req) });
});

// Serve login page for unauthenticated users, app for authenticated
app.use((req, res, next) => {
  // Allow API routes through (they handle their own auth)
  if (req.path.startsWith("/api/")) return next();
  // Allow the login page assets
  if (req.path === "/login.html") return next();
  // Check auth
  if (!isAuthed(req)) {
    return res.redirect("/login.html");
  }
  next();
});

app.use(express.static(path.join(__dirname, "public")));

// Parse transactions from PDF text - extracts date, IDs, and amount per block
function parseTransactions(text) {
  const normalized = text.replace(/\r\n/g, "\n");

  // Split into transaction blocks by date pattern DD/MM/YYYY
  const blocks = normalized.split(/(?=\d{2}\/\d{2}\/\d{4})/).filter((b) => b.trim());

  const transactions = [];
  const anomalies = [];

  for (const block of blocks) {
    const dateMatch = block.match(/^(\d{2}\/\d{2}\/\d{4})/);
    if (!dateMatch) continue;

    const date = dateMatch[1];

    // Extract amount: number with decimal before newline
    const amountMatch = block.match(/(\d+\.\d{1,2})\s*\n/);
    const amount = amountMatch ? parseFloat(amountMatch[1]) : null;

    // Extract IDs: M/m + 3-6 digits, NOT followed by a dot (avoids 120.0 -> M120)
    const idMatches = [];
    const idRegex = /[Mm](\d{3,6})(?!\.\d)/g;
    let m;
    while ((m = idRegex.exec(block)) !== null) {
      idMatches.push("M" + m[1]);
    }

    // Also catch M separated by newline/space from digits
    const splitRegex = /[Mm][\s\n](\d{3,6})(?!\.\d)/g;
    while ((m = splitRegex.exec(block)) !== null) {
      idMatches.push("M" + m[1]);
    }

    const uniqueIds = [...new Set(idMatches)];

    if (uniqueIds.length === 0) {
      // No student ID found - this is an anomaly
      const refSnippet = block.replace(/^[\d\/]+\d{16}/, "").split("Faster Payment")[0].trim();
      anomalies.push({ date, amount, reference: refSnippet || "(unknown)" });
    } else {
      // Each ID in this block gets the same date/amount
      for (const id of uniqueIds) {
        transactions.push({ id, date, amount });
      }
    }
  }

  return { transactions, anomalies };
}

// Parse student list from Excel buffer
function parseStudentList(buffer) {
  const wb = XLSX.read(buffer, { type: "buffer" });
  const ws = wb.Sheets[wb.SheetNames[0]];
  const rows = XLSX.utils.sheet_to_json(ws);
  const students = [];
  for (const row of rows) {
    const id = String(row["Student ID"] || "").trim().toUpperCase();
    const name = String(row["Student Name"] || "").trim();
    if (id) students.push({ id, name });
  }
  return students;
}

// Escape CSV field
function csvField(val) {
  const s = String(val == null ? "" : val);
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

// Auth guard for API routes
function requireAuth(req, res, next) {
  if (!isAuthed(req)) return res.status(401).json({ error: "Not authenticated" });
  next();
}

// Match endpoint: PDF + Excel -> matched results + CSV
app.post("/api/match", requireAuth, upload.fields([{ name: "pdf" }, { name: "excel" }]), async (req, res) => {
  try {
    const pdfFile = req.files?.pdf?.[0];
    const excelFile = req.files?.excel?.[0];
    if (!pdfFile) return res.status(400).json({ error: "No PDF file uploaded" });
    if (!excelFile) return res.status(400).json({ error: "No Excel file uploaded" });

    const pdfData = await pdfParse(pdfFile.buffer);
    const { transactions, anomalies } = parseTransactions(pdfData.text);
    const students = parseStudentList(excelFile.buffer);
    const studentMap = new Map(students.map((s) => [s.id, s.name]));

    // Matched: transactions where ID exists in student list
    const matched = [];
    // Unmatched PDF IDs (in PDF but not student list)
    const unmatchedPdf = [];

    for (const tx of transactions) {
      if (studentMap.has(tx.id)) {
        matched.push({ ...tx, name: studentMap.get(tx.id) });
      } else {
        unmatchedPdf.push(tx);
      }
    }

    // Find duplicates within matched (same ID appears multiple times)
    const idCount = {};
    for (const m of matched) {
      idCount[m.id] = (idCount[m.id] || 0) + 1;
    }
    const dupeIds = new Set(Object.keys(idCount).filter((id) => idCount[id] > 1));

    // Separate singles from dupes
    const singles = matched.filter((m) => !dupeIds.has(m.id));
    const dupes = matched.filter((m) => dupeIds.has(m.id));

    // Students not found in PDF (didn't pay)
    const pdfIdSet = new Set(transactions.map((t) => t.id));
    const notPaid = students.filter((s) => !pdfIdSet.has(s.id));

    // Build CSV
    const csvLines = [];
    // Header row - main data left, anomalies right
    csvLines.push("ID,Student Name,Amount,Date,,,Anomaly Type,Reference,Amount,Date");

    // Singles first
    let row = 0;
    const anomalyStart = row;
    const rightSide = [];

    // Collect right-side data: unknown PDF IDs + no-ID anomalies + not-paid students
    for (const u of unmatchedPdf) {
      rightSide.push({ type: "Unknown ID", ref: u.id, amount: u.amount, date: u.date });
    }
    for (const a of anomalies) {
      rightSide.push({ type: "No Student ID", ref: a.reference, amount: a.amount, date: a.date });
    }
    for (const s of notPaid) {
      rightSide.push({ type: "Not Paid", ref: s.id + " - " + s.name, amount: "", date: "" });
    }

    // Merge left and right side row by row
    const leftRows = [];
    for (const s of singles) {
      leftRows.push([s.id, s.name, s.amount, s.date]);
    }
    // Blank separator before dupes
    if (dupes.length > 0 && singles.length > 0) {
      leftRows.push(["", "", "", ""]);
      leftRows.push(["--- DUPLICATES ---", "", "", ""]);
    }
    for (const d of dupes) {
      leftRows.push([d.id, d.name, d.amount, d.date]);
    }

    const maxRows = Math.max(leftRows.length, rightSide.length);
    for (let i = 0; i < maxRows; i++) {
      const left = leftRows[i] || ["", "", "", ""];
      const right = rightSide[i];
      const leftCsv = left.map(csvField).join(",");
      if (right) {
        csvLines.push(leftCsv + ",,," + [right.type, right.ref, right.amount, right.date].map(csvField).join(","));
      } else {
        csvLines.push(leftCsv);
      }
    }

    const csv = csvLines.join("\n");

    res.json({
      pdfFilename: pdfFile.originalname,
      excelFilename: excelFile.originalname,
      pdfPages: pdfData.numpages,
      totalTransactions: transactions.length,
      totalStudents: students.length,
      matched: singles,
      dupes,
      unmatchedPdf,
      anomalies,
      notPaid,
      csv,
    });
  } catch (err) {
    console.error("Match error:", err.message);
    res.status(500).json({ error: "Failed to match: " + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`MUAI Finance server running at http://localhost:${PORT}`);
});
