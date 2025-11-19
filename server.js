import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
//import os from "os";
import cors from "cors";
import multer from "multer";
import { createRequire } from "module";
import pgPromise from "pg-promise";
import { randomUUID } from "crypto";

const require = createRequire(import.meta.url);
const pdfParse = require("pdf-parse");
const pgSession = require("connect-pg-simple")(session);

dotenv.config();

/* ============================
   BASIC APP + DB BOOTSTRAP
   ============================ */

const app = express();
const PORT = process.env.PORT || 4000;

const upload = multer({ storage: multer.memoryStorage() });


const pgp = pgPromise();

// Render PostgreSQL requires SSL
const db = pgp({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

db.connect()
  .then(obj => {
    console.log("✅ Connected to PostgreSQL");
    obj.done();
  })
  .catch(error => {
    console.error("❌ PostgreSQL connection error:", error);
  });


/* ============================
   PDF PARSER (multi product / multi page)
   ============================ */

function parseEuroNumber(raw) {
  if (!raw) return 0;
  const cleaned = String(raw).replace(/\./g, "").replace(",", ".");
  const n = parseFloat(cleaned);
  return isNaN(n) ? 0 : n;
}

function parseSingleProductBlock(lines, sheetNumber, orderNumber) {
  const prodHeaderIdx = lines.findIndex((l) => l.startsWith("ΠΡΟΙΟΝ"));
  if (prodHeaderIdx === -1) return null;

  const productLine =
    (lines[prodHeaderIdx + 1] && lines[prodHeaderIdx + 1].trim()) || "";

  const productId = productLine.split(/\s+/)[0];

  // --- Quantity (line with TE) ---
  let quantity = 0;
  const qtyLine = lines.find(
    (l) => /(ΤΕ|TE|ΤE|TΕ)/.test(l) && /\d+[.,]\d+/.test(l)
  );
  if (qtyLine) {
    const qm = qtyLine.match(/(\d+[.,]\d+)\s+(ΤΕ|TE|ΤE|TΕ)/);
    if (qm) quantity = parseEuroNumber(qm[1]);
  }

  // --- Materials & T-lines ---
  const mRegex = /^M\s+(\d+)\s+\d+\s+(\S+)\s+([\d.,]+)/;
  const materialsRaw = [];
  const yields = {};
  let lastMaterialPos = null;

  for (const line of lines) {
    const m = line.match(mRegex);
    if (m) {
      const pos = m[1];
      const materialId = m[2];
      const totalQty = parseEuroNumber(m[3]);

      materialsRaw.push({ pos, materialId, totalQty });
      lastMaterialPos = pos;
      continue;
    }

    if (line.startsWith("T")) {
      let rest = line.replace(/^T\s+/, "").trim();
      let ratio = 0;

      const firstNum = rest.match(/^(\d+)\b/);
      if (firstNum && lastMaterialPos && firstNum[1] === lastMaterialPos) {
        rest = rest.slice(firstNum[0].length).trim();
      } else if (lastMaterialPos && rest.startsWith(lastMaterialPos)) {
        rest = rest.slice(lastMaterialPos.length).trim();
      }

      let mm = rest.match(
        /(\d+(?:[.,]\d+)?)\s*(Τ\/Φ|τ\/φ|T\/F|ΤΕΜ|τεμ|TEM)/i
      );
      if (mm) {
        ratio = parseEuroNumber(mm[1]);
      } else {
        mm = rest.match(/(τεμ|ΤΕΜ|TEM)\s+(\d+(?:[.,]\d+)?)/i);
        if (mm) {
          ratio = parseEuroNumber(mm[2]);
        }
      }

      if (!ratio) {
        const nums = rest.match(/\d+(?:[.,]\d+)?/g);
        if (nums && nums.length) {
          ratio = parseEuroNumber(nums[nums.length - 1]);
        }
      }

      if (ratio > 0 && lastMaterialPos) {
        yields[lastMaterialPos] = ratio;
      }
    }
  }

  const materials = materialsRaw.map((mat) => {
    let perPiece = 0;
    if (yields[mat.pos]) {
      perPiece = 1 / yields[mat.pos];
    } else if (quantity > 0) {
      perPiece = mat.totalQty / quantity;
    }
    return {
      materialId: mat.materialId,
      quantityPerPiece: perPiece,
    };
  });

  // --- Phases (A-lines) ---
  const phases = [];
  const phaseRegex =
    /^A\s+\d+\s+\d+\s+\S+\s+(\d+)\s+([\d.,]+)\s+M\s+([\d.,]+)/;

  for (const line of lines) {
    if (!line.startsWith("A ")) continue;
    const m = line.match(phaseRegex);
    if (!m) continue;

    const phaseId = m[1];
    const setupMin = parseEuroNumber(m[2]);
    const prodMin = parseEuroNumber(m[3]);

    phases.push({
      phaseId,
      setupTime: setupMin,
      productionTimePerPiece:
        quantity > 0 ? Number((prodMin / quantity).toFixed(2)) : 0,
    });
  }

  if (!quantity && materials.length === 0 && phases.length === 0) {
    return null;
  }

  return {
    sheetNumber,
    quantity,
    productDef: {
      id: productId,
      name: productId,
      materials,
      phases,
    },
  };
}

function parseOrderPdfText(text) {
  const lines = (text || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  console.log("===== DEBUG LINES =====");
  lines.forEach((l, i) => console.log(i, JSON.stringify(l)));

  let orderNumber = "";
  const projektIdx = lines.findIndex((l) => l.startsWith("Projekt"));
  if (projektIdx >= 0) {
    const next = lines[projektIdx + 1] || "";
    const m = next.match(/([A-Z0-9]+)\s*\/\s*(\d+)/);
    if (m) {
      orderNumber = m[2];
    }
  }

  if (!orderNumber || orderNumber.trim() === "") {
    const dm = text.match(
      /Datum\s*[:.]?\s*([0-9]{2}\.[0-9]{2}\.[0-9]{2})/i
    );
    const dateStr = dm ? dm[1] : "UNKNOWN";
    orderNumber = `NO-ORD-${dateStr}`;
    console.log("⚠️ No order number in PDF, using:", orderNumber);
  }

  const blocks = [];
  let currentSheetNumber = "";
  let currentHeaderStart = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.includes("ΑΡ.ΑΝΑΦΟΡΑΣ") || line.includes("ΑΡ.ΕΝΤΟΛΗΣ")) {
      currentHeaderStart = i;
      const next = lines[i + 1] || "";
      const nums = next.match(/\d+/g) || [];
      if (nums.length >= 2) {
        currentSheetNumber = nums[1];
      }
    }

    if (line.startsWith("ΠΡΟΙΟΝ")) {
      const start = currentHeaderStart;
      let j = i + 1;
      while (j < lines.length) {
        const l2 = lines[j];
        if (l2.includes("ΑΡ.ΑΝΑΦΟΡΑΣ") || l2.includes("ΑΡ.ΕΝΤΟΛΗΣ")) break;
        j++;
      }
      const blockLines = lines.slice(start, j);
      blocks.push({ sheetNumber: currentSheetNumber, lines: blockLines });
    }
  }

  if (blocks.length === 0) {
    throw new Error("No products found in PDF");
  }

  const sheetsMap = new Map();

  for (const block of blocks) {
    const sheet = parseSingleProductBlock(
      block.lines,
      block.sheetNumber,
      orderNumber
    );
    if (!sheet) continue;

    const key = `${sheet.sheetNumber}__${sheet.productDef.id}`;
    const existing = sheetsMap.get(key);

    if (!existing) {
      sheetsMap.set(key, sheet);
    } else {
      existing.productDef.materials = [
        ...existing.productDef.materials,
        ...sheet.productDef.materials,
      ];
      existing.productDef.phases = [
        ...existing.productDef.phases,
        ...sheet.productDef.phases,
      ];
      if (!existing.quantity && sheet.quantity) {
        existing.quantity = sheet.quantity;
      }
    }
  }

  const sheets = Array.from(sheetsMap.values());
  if (sheets.length === 0) {
    throw new Error("Failed to parse any product sheets");
  }

  return {
    orderNumber,
    sheets,
  };
}

/* ============================
   CORS & MIDDLEWARE
   ============================ 

function getLocalIPs() {
  const nets = os.networkInterfaces();
  const results = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === "IPv4" && !net.internal) {
        results.push(`http://${net.address}:3000`);
        results.push(`https://${net.address}:3000`);
      }
    }
  }
  return results;
}
*/
const envAllowed = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

let codespaceOrigin = null;
if (
  process.env.CODESPACE_NAME &&
  process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN
) {
  codespaceOrigin = `https://${process.env.CODESPACE_NAME}-3000.${process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}`;
}

const allowedOrigins = [
  "http://localhost:3000",
  "https://localhost:3000",
  "http://127.0.0.1:3000",
  "https://127.0.0.1:3000",
  ...(codespaceOrigin ? [codespaceOrigin] : []),
  //...getLocalIPs(),
  ...envAllowed,
];

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (
        allowedOrigins.some((a) => origin.startsWith(a)) ||
        origin.includes("app.github.dev")
      ) {
        return callback(null, true);
      }
      console.warn("❌ Blocked by CORS:", origin);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Credentials", "true");
    if (req.headers.origin)
      res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    );
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type,Authorization"
    );
    return res.sendStatus(204);
  }
  next();
});

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Credentials", "true");
  if (req.headers.origin)
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  next();
});

app.use(express.json());

/* ============================
   SESSION (PostgreSQL store)
   ============================ */

const SESSION_SECRET =
  process.env.SESSION_SECRET || "warehouse-secret-key-default";

app.use(
  session({
    store: new pgSession({
      pool: db.$pool,
      tableName: "session",
      createTableIfMissing: true,
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // true on Render
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 86400000,
    },
  })
);

/* ============================
   DB INIT (PostgreSQL, UUID)
   ============================ */

async function initDB() {
  // Create tables
  await db.none(`
    CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('manager','operator','storekeeper','orderkeeper','machineoperator','infraoperator')),
      allowed_tabs JSONB NOT NULL,
      last_login TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS items (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      sku TEXT NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 0,
      price DOUBLE PRECISION NOT NULL DEFAULT 0,
      category TEXT,
      area TEXT,
      position TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id UUID PRIMARY KEY,
      item_id UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      delta INTEGER NOT NULL,
      reason TEXT,
      "user" TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      materials_json JSONB NOT NULL,
      phases_json JSONB NOT NULL
    );

    CREATE TABLE IF NOT EXISTS orders (
      order_number TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS production_sheets (
      id UUID PRIMARY KEY,
      order_number TEXT NOT NULL REFERENCES orders(order_number) ON DELETE CASCADE,
      production_sheet_number TEXT NOT NULL,
      product_id TEXT NOT NULL REFERENCES products(id),
      quantity INTEGER NOT NULL,
      qr_value TEXT NOT NULL,
      product_snapshot_json JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS phases (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS phase_logs (
      id UUID PRIMARY KEY,
      operator_username TEXT NOT NULL,
      order_number TEXT NOT NULL,
      production_sheet_number TEXT NOT NULL,
      product_id TEXT NOT NULL,
      phase_id TEXT NOT NULL REFERENCES phases(id) ON DELETE CASCADE,
      start_time TIMESTAMPTZ NOT NULL,
      end_time TIMESTAMPTZ,
      quantity_done INTEGER NOT NULL DEFAULT 0,
      total_quantity INTEGER NOT NULL,
      find_material_time INTEGER,
      setup_time INTEGER DEFAULT 0,
      production_time INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS live_phase_log (
      id UUID PRIMARY KEY,
      username TEXT NOT NULL,
      sheet_id UUID NOT NULL REFERENCES production_sheets(id) ON DELETE CASCADE,
      product_id TEXT NOT NULL,
      phase_id TEXT NOT NULL,
      planned_time DOUBLE PRECISION NOT NULL,
      start_time TIMESTAMPTZ NOT NULL,
      end_time TIMESTAMPTZ,
      status TEXT
    );

  CREATE TABLE IF NOT EXISTS material_history (
    id UUID PRIMARY KEY,
    material_id UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details JSONB NOT NULL
  );

    CREATE INDEX IF NOT EXISTS idx_items_sku ON items(sku);
    CREATE INDEX IF NOT EXISTS idx_orders_number ON orders(order_number);
    CREATE INDEX IF NOT EXISTS idx_transactions_item ON transactions(item_id);
  `);
  
  

  // Trigger for updated_at
  await db.none(`
    CREATE OR REPLACE FUNCTION set_items_updated_at()
    RETURNS TRIGGER AS $$
    BEGIN
      NEW.updated_at = NOW();
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS trg_items_updated_at ON items;
    CREATE TRIGGER trg_items_updated_at
    BEFORE UPDATE ON items
    FOR EACH ROW
    EXECUTE FUNCTION set_items_updated_at();
  `);


  // Ensure default Manager user
  const { count: userCount } = await db.one(
    `SELECT COUNT(*)::int AS count FROM users`
  );
  if (userCount === 0) {
    const hashed = await bcrypt.hash("Manager", 10);
    const managerId = randomUUID();
    const tabs = [
      "transactions",
      "operator",
      "search",
      "history",
      "batch-create",
      "manager",
      "orders",
      "scan-product-sheet",
      "daily-logs",
      "phase-manager",
      "pdf-import",
    ];
    await db.none(
      `
      INSERT INTO users (id, username, password, role, allowed_tabs)
      VALUES ($1, 'Manager', $2, 'manager', $3)
    `,
      [managerId, hashed, JSON.stringify(tabs)]
    );
    console.log(
      "👑 Default Manager user created (username: Manager / password: Manager)"
    );
  }

  // Ensure default phases
  const { count: phaseCount } = await db.one(
    `SELECT COUNT(*)::int AS count FROM phases`
  );
  if (phaseCount === 0) {
    const defaultPhases = [
      { id: "1", name: "ΨΑΛΙΔΙ" },
      { id: "2", name: "ΔΙΑΤΡΗΤΙΚΑ" },
      { id: "3", name: "ΔΙΑΜΟΡΦΩΣΗ" },
      { id: "4", name: "ΣΤΡΑΝΤΖΕΣ" },
      { id: "5", name: "ΣΤΡΑΝΤΖΑ ΧΕΙΡ." },
      { id: "6", name: "ΠΟΝΤΑ" },
      { id: "7", name: "ΠΟΝΤΑ ΚΡΕΜ" },
      { id: "8", name: "TIG" },
      { id: "9", name: "MIG" },
      { id: "10", name: "ΒΟΥΡΤΣΑ" },
      { id: "11", name: "PEM" },
      { id: "12", name: "ΣΠΕΙΡΩΜΑΤΑ" },
      { id: "13", name: "ΔΡΑΠΑΝΑ" },
      { id: "14", name: "ΠΟΛΥΔΡΑΠΑΝΟ" },
      { id: "15", name: "ΔΙΣΚΟΠΡΙΟΝΟ" },
      { id: "16", name: "ΠΡΕΣΣΑ" },
      { id: "17", name: "ΔΙΑΤΡΗΤΙΚΟ ΑΕΡΟΣ" },
      { id: "18", name: "ΓΩΝΙΟΚΟΠΤΗΣ" },
      { id: "19", name: "ΒΑΦΕΙΟ" },
      { id: "20", name: "ΣΥΣΚΕΥΑΣΙΑ" },
      { id: "21", name: "Μ/Τα" },
      { id: "22", name: "CAD-CAM" },
      { id: "23", name: "ALODIN" },
      { id: "24", name: "ΑΠΟΛΑΔΩΣΗ" },
      { id: "25", name: "ΦΡΕΖΑ" },
      { id: "26", name: "ΔΟΝΗΤΗΣ" },
      { id: "27", name: "ΠΑΝΤΟΓΡΑΦΟΣ" },
      { id: "28", name: "ΨΥΧΡΟ ΓΑΛΒΑΝΙΣΜΑ" },
      { id: "30", name: "LASER" },
    ];

    const cs = new pgp.helpers.ColumnSet(["id", "name"], {
      table: "phases",
    });
    const insert = pgp.helpers.insert(defaultPhases, cs);
    await db.none(insert);
    console.log(
      "⚙️ Default phases inserted:",
      defaultPhases.map((p) => p.name).join(", ")
    );
  }

  console.log("✅ Database initialized");
}

/* ============================
   HEALTH CHECK
   ============================ */

app.get("/health", (req, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);

/* ============================
   ITEMS CRUD
   ============================ */

app.get("/items", async (req, res, next) => {
  try {
    const { q = "", limit = 100, offset = 0 } = req.query;
    const lim = Number(limit) || 100;
    const off = Number(offset) || 0;

    let rows;
    if (q) {
      const term = `%${q}%`;
      rows = await db.any(
        `
        SELECT * FROM items
        WHERE name ILIKE $1 OR sku ILIKE $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
      `,
        [term, lim, off]
      );
    } else {
      rows = await db.any(
        `
        SELECT * FROM items
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
      `,
        [lim, off]
      );
    }
    res.json(rows);
  } catch (e) {
    next(e);
  }
});

app.get("/items/:id", async (req, res, next) => {
  try {
    const row = await db.oneOrNone(
      `SELECT * FROM items WHERE id = $1`,
      req.params.id
    );
    if (!row) return res.status(404).json({ error: "Item not found" });
    res.json(row);
  } catch (e) {
    next(e);
  }
});

app.get("/api/materials/search", async (req, res) => {
  try {
    const term = (req.query.q || "").toString().trim();

    const rows = await db.any(
      `
      SELECT *
      FROM items
      WHERE sku ILIKE $1 OR name ILIKE $1
      ORDER BY sku ASC
      LIMIT 100
      `,
      [`%${term}%`]
    );

    // If no results, return empty list
    if (rows.length === 0) {
      return res.json([]);
    }

    // Get all material IDs
    const ids = rows.map(r => r.id);

    // Load all history entries
    const historyRows = await db.any(
      `
      SELECT id, material_id, event_type, timestamp, details
      FROM material_history
      WHERE material_id IN ($1:csv)
      ORDER BY timestamp ASC
      `,
      [ids]
    );

    // Group history by material_id
    const historyMap = {};
    for (const h of historyRows) {
      if (!historyMap[h.material_id]) historyMap[h.material_id] = [];
      historyMap[h.material_id].push({
        type: h.event_type,
        timestamp: h.timestamp,
        details: h.details
      });
    }

    // Build frontend-ready material objects
    const materials = rows.map((i) => ({
      id: String(i.id),
      materialCode: i.sku || i.name,
      initialQuantity: i.quantity,
      currentQuantity: i.quantity,
      location:
        i.area && i.position ? { area: i.area, position: i.position } : null,
      history: [
        {
          type: "CREATED",
          timestamp: i.created_at,
          details: { quantity: i.quantity }
        },
        ...(historyMap[i.id] || [])
      ]
    }));

    res.json(materials);
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ error: "Database search failed" });
  }
});



app.post("/items", async (req, res, next) => {
  try {
    const {
      name,
      sku = null,
      quantity = 0,
      price = 0,
      category = null,
    } = req.body;
    if (!name) return res.status(400).json({ error: "name is required" });

    const id = randomUUID();
    await db.none(
      `
      INSERT INTO items (id, name, sku, quantity, price, category)
      VALUES ($1, $2, $3, $4, $5, $6)
    `,
      [id, name, sku, Number(quantity), Number(price), category]
    );

    const created = await db.one(
      `SELECT * FROM items WHERE id = $1`,
      id
    );
    res.status(201).json(created);
  } catch (e) {
    next(e);
  }
});

app.put("/items/:id", async (req, res, next) => {
  try {
    const { name, sku, quantity, price, category, area, position } = req.body;
    const result = await db.result(
      `
      UPDATE items
      SET name=$1, sku=$2, quantity=$3, price=$4, category=$5, area=$6, position=$7
      WHERE id=$8
    `,
      [
        name,
        sku,
        quantity,
        price,
        category,
        area,
        position,
        req.params.id,
      ]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Item not found" });

    const updated = await db.one(
      `SELECT * FROM items WHERE id = $1`,
      req.params.id
    );
    res.json(updated);
  } catch (e) {
    next(e);
  }
});

app.patch("/items/:id/adjust", async (req, res, next) => {
  try {
    const { delta, reason = null, user = null } = req.body;
    if (delta == null)
      return res.status(400).json({ error: "delta is required" });

    const item = await db.oneOrNone(
      `SELECT * FROM items WHERE id = $1`,
      req.params.id
    );
    if (!item) return res.status(404).json({ error: "Item not found" });

    const newQty = item.quantity + Number(delta);
    if (newQty < 0)
      return res
        .status(400)
        .json({ error: "Resulting quantity would be negative" });

    await db.tx(async (t) => {
      await t.none(
        `UPDATE items SET quantity = $1 WHERE id = $2`,
        [newQty, req.params.id]
      );
      await t.none(
        `
        INSERT INTO transactions (id, item_id, delta, reason, "user")
        VALUES ($1, $2, $3, $4, $5)
      `,
        [randomUUID(), req.params.id, delta, reason, user]
      );
    });

    const updated = await db.one(
      `SELECT * FROM items WHERE id = $1`,
      req.params.id
    );
    res.json(updated);
  } catch (e) {
    next(e);
  }
});

app.delete("/items/:id", async (req, res, next) => {
  try {
    const result = await db.result(
      `DELETE FROM items WHERE id = $1`,
      req.params.id
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Item not found" });
    res.status(204).send();
  } catch (e) {
    next(e);
  }
});

/* ============================
   USERS + AUTH
   ============================ */

app.get("/users", async (req, res, next) => {
  try {
    const rows = await db.any(
      "SELECT * FROM users ORDER BY created_at ASC"
    );
    res.json(
      rows.map((u) => ({
        ...u,
        allowedTabs: u.allowed_tabs || [],
      }))
    );
  } catch (e) {
    next(e);
  }
});

app.post("/users", async (req, res, next) => {
  try {
    const { username, password, role, allowedTabs } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const id = randomUUID();

    await db.none(
      `
      INSERT INTO users (id, username, password, role, allowed_tabs)
      VALUES ($1, $2, $3, $4, $5)
    `,
      [id, username, hashed, role, JSON.stringify(allowedTabs || [])]
    );

    const created = await db.one(
      "SELECT * FROM users WHERE id = $1",
      id
    );
    res.status(201).json({
      ...created,
      allowedTabs: created.allowed_tabs || [],
    });
  } catch (e) {
    next(e);
  }
});

app.put("/users/:id", async (req, res, next) => {
  try {
    const { password, role, allowedTabs } = req.body;
    const updates = [];
    const params = [];
    let idx = 1;

    if (password) {
      const hashed = await bcrypt.hash(password, 10);
      updates.push(`password = $${idx++}`);
      params.push(hashed);
    }
    if (role) {
      updates.push(`role = $${idx++}`);
      params.push(role);
    }
    if (allowedTabs) {
      updates.push(`allowed_tabs = $${idx++}`);
      params.push(JSON.stringify(allowedTabs));
    }

    if (updates.length === 0)
      return res.status(400).json({ error: "No updates provided" });

    params.push(req.params.id);

    const result = await db.result(
      `UPDATE users SET ${updates.join(", ")} WHERE id = $${idx}`,
      params
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "User not found" });

    const updated = await db.one(
      "SELECT * FROM users WHERE id = $1",
      req.params.id
    );
    res.json({
      ...updated,
      allowedTabs: updated.allowed_tabs || [],
    });
  } catch (e) {
    next(e);
  }
});

app.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const user = await db.oneOrNone(
      "SELECT * FROM users WHERE username = $1",
      username
    );
    if (!user)
      return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(401).json({ error: "Invalid credentials" });

    await db.none(
      "UPDATE users SET last_login = NOW() WHERE id = $1",
      user.id
    );

    req.session.userId = user.id;
    res.json({
      id: user.id,
      username: user.username,
      role: user.role,
      allowedTabs: user.allowed_tabs || [],
      lastLogin: user.last_login,
    });
  } catch (e) {
    next(e);
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("❌ Session destroy error:", err);
      return res.status(500).json({ error: "Failed to logout" });
    }

    res.clearCookie("connect.sid", {
      path: "/",
      httpOnly: true,
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      secure: process.env.NODE_ENV === "production",
    });

    res.status(200).json({ ok: true, message: "Logged out" });
  });
});

app.get("/session", async (req, res, next) => {
  try {
    if (!req.session.userId)
      return res.status(401).json({ error: "Not logged in" });

    const user = await db.oneOrNone(
      "SELECT * FROM users WHERE id = $1",
      req.session.userId
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({
      id: user.id,
      username: user.username,
      role: user.role,
      allowedTabs: user.allowed_tabs || [],
      lastLogin: user.last_login,
    });
  } catch (e) {
    next(e);
  }
});

/* ============================
   TRANSACTIONS
   ============================ */

app.get("/transactions", async (req, res, next) => {
  try {
    const rows = await db.any(
      `SELECT * FROM transactions ORDER BY created_at DESC LIMIT 500`
    );
    res.json(rows);
  } catch (e) {
    next(e);
  }
});

/* ============================
   PRODUCTS
   ============================ */

app.get("/products", async (req, res, next) => {
  try {
    const rows = await db.any("SELECT * FROM products");
    res.json(
      rows.map((r) => ({
        id: r.id,
        name: r.name,
        materials: r.materials_json,
        phases: r.phases_json,
      }))
    );
  } catch (e) {
    next(e);
  }
});

app.post("/products", async (req, res, next) => {
  try {
    const { id, name, materials, phases } = req.body;

    const jsonMaterials = JSON.stringify(materials || []);
    const jsonPhases = JSON.stringify(phases || []);

    const existing = await db.oneOrNone(
      `SELECT id FROM products WHERE id = $1`,
      id
    );

    if (existing) {
      await db.none(
        `
        UPDATE products
        SET name=$1, materials_json=$2, phases_json=$3
        WHERE id = $4
        `,
        [name || id, jsonMaterials, jsonPhases, id]
      );
    } else {
      await db.none(
        `
        INSERT INTO products (id, name, materials_json, phases_json)
        VALUES ($1, $2, $3, $4)
        `,
        [id, name || id, jsonMaterials, jsonPhases]
      );
    }

    const updated = await db.one(
      `SELECT * FROM products WHERE id = $1`,
      id
    );

    res.status(existing ? 200 : 201).json({
      id: updated.id,
      name: updated.name,
      materials: updated.materials_json,
      phases: updated.phases_json,
    });

  } catch (e) {
    next(e);
  }
});


/* ============================
   ORDERS
   ============================ */

app.get("/orders", async (req, res, next) => {
  try {
    const rows = await db.any(
      `
      SELECT order_number AS "orderNumber",
             created_at AS "createdAt"
      FROM orders
      ORDER BY created_at DESC
    `
    );
    res.json(rows);
  } catch (e) {
    next(e);
  }
});

app.post("/orders", async (req, res, next) => {
  try {
    const { orderNumber } = req.body;
    if (!orderNumber || orderNumber.trim() === "")
      return res.status(400).json({ error: "orderNumber is required" });

    await db.none(
      `
      INSERT INTO orders (order_number)
      VALUES ($1)
      ON CONFLICT (order_number) DO NOTHING
    `,
      orderNumber.trim()
    );

    const created = await db.one(
      `
      SELECT order_number AS "orderNumber",
             created_at  AS "createdAt"
      FROM orders
      WHERE order_number = $1
    `,
      orderNumber.trim()
    );

    res.status(201).json(created);
  } catch (e) {
    next(e);
  }
});

/* ============================
   PRODUCTION SHEETS
   ============================ */

app.get("/production_sheets/:orderNumber", async (req, res, next) => {
  try {
    const rows = await db.any(
      `
      SELECT *
      FROM production_sheets
      WHERE order_number = $1
    `,
      req.params.orderNumber
    );
	res.json(rows.map(r => ({
	  id: r.id,
	  orderNumber: r.order_number,
	  productionSheetNumber: r.production_sheet_number,
	  productId: r.product_id,
	  quantity: r.quantity,
	  qrValue: r.qr_value,
	  createdAt: r.created_at
	})));
  } catch (e) {
    next(e);
  }
});

app.get("/production_sheet_by_qr/:qr", async (req, res, next) => {
  try {
    const { qr } = req.params;

    const sheet = await db.oneOrNone(
      `SELECT * FROM production_sheets WHERE qr_value = $1`,
      qr
    );
    if (!sheet)
      return res.status(404).json({ error: "Production sheet not found" });

    const order = await db.oneOrNone(
      `SELECT order_number FROM orders WHERE order_number = $1`,
      sheet.order_number
    );

    sheet.orderNumber = order?.order_number || sheet.order_number;

    let product = null;
    if (sheet.product_snapshot_json) {
      product = sheet.product_snapshot_json;
    } else {
      const row = await db.oneOrNone(
        `SELECT * FROM products WHERE id = $1`,
        sheet.product_id
      );
      if (row) {
        product = {
          id: row.id,
          name: row.name,
          materials: row.materials_json,
          phases: row.phases_json,
        };
      }
    }

    const phaseLogs = await db.any(
      `
      SELECT *
      FROM phase_logs
      WHERE production_sheet_number = $1
      ORDER BY start_time DESC
    `,
      sheet.production_sheet_number
    );

	res.json({
	  id: sheet.id,
	  qrValue: sheet.qr_value,
	  productionSheetNumber: sheet.production_sheet_number,  // FIX
	  productId: sheet.product_id,                           // FIX
	  quantity: sheet.quantity,
	  orderNumber: sheet.order_number,
	  product: product
		? {
			id: product.id,
			name: product.name,
			materials: product.materials,
			phases: product.phases,
		  }
		: null,
	  phaseLogs
	});

  } catch (e) {
    next(e);
  }
});

app.post("/production_sheets", async (req, res, next) => {
  try {
    const { orderNumber, sheets } = req.body;
    const createdSheets = [];

    await db.tx(async (t) => {

      // Create order if missing
      const existingOrder = await t.oneOrNone(
        `SELECT order_number FROM orders WHERE order_number = $1`,
        orderNumber
      );
      if (!existingOrder) {
        await t.none(
          `INSERT INTO orders (order_number) VALUES ($1)`,
          orderNumber
        );
        console.log(`🆕 Created order ${orderNumber}`);
      }

      for (const s of sheets) {

        // --- PRODUCT CREATION ---
		if (s.productDef && s.productDef.id) {
		  const existingProduct = await t.oneOrNone(
			`SELECT id FROM products WHERE id = $1`,
			s.productDef.id
		  );

		  const jsonMaterials = JSON.stringify(s.productDef.materials || []);
		  const jsonPhases = JSON.stringify(s.productDef.phases || []);

		  if (!existingProduct) {
			await t.none(
			  `
			  INSERT INTO products (id, name, materials_json, phases_json)
			  VALUES ($1, $2, $3, $4)
			  `,
			  [
				s.productDef.id,
				s.productDef.name || s.productDef.id,
				jsonMaterials,
				jsonPhases
			  ]
			);
			console.log(`🆕 Created product ${s.productDef.id}`);
		  }
		}


        // --- PRODUCTION SHEET CREATION ---
        const id = randomUUID();

        const qrValue = JSON.stringify({
          productionSheetId: id,
          orderNumber: orderNumber,
          productId: s.productId,
        });

        await t.none(
          `
          INSERT INTO production_sheets
          (id, order_number, production_sheet_number, product_id, quantity, qr_value, product_snapshot_json)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          `,
          [
            id,
            orderNumber,
            s.productionSheetNumber,
            s.productId,
            s.quantity,
            qrValue,
            JSON.stringify(s.productDef || {})
          ]
        );

		const created = await t.one(
		  `SELECT * FROM production_sheets WHERE id = $1`,
		  id
		);

		createdSheets.push({
		  id: created.id,
		  orderNumber: created.order_number,
		  productionSheetNumber: created.production_sheet_number,
		  productId: created.product_id,
		  quantity: created.quantity,
		  qrValue: created.qr_value,
		  productSnapshot: created.product_snapshot_json
		});
      }
    });

    res.status(201).json(createdSheets);

  } catch (err) {
    console.error("❌ Failed to insert production sheets:", err);
    next(err);
  }
});

/* ============================
   PHASES + MANAGEMENT
   ============================ */

app.get("/phases", async (req, res, next) => {
  try {
    const rows = await db.any("SELECT * FROM phases ORDER BY id::int ASC");
    res.json(rows);
  } catch (e) {
    next(e);
  }
});

app.post("/phases", async (req, res, next) => {
  try {
    const { phases } = req.body;
    await db.tx(async (t) => {
      for (const p of phases) {
        await t.none(
          `
          INSERT INTO phases (id, name)
          VALUES ($1, $2)
          ON CONFLICT (id)
          DO UPDATE SET name = EXCLUDED.name
        `,
          [p.id, p.name]
        );
      }
    });
    res.json(phases);
  } catch (e) {
    next(e);
  }
});

app.post("/phases/create", async (req, res, next) => {
  try {
    const { id, name } = req.body;
    if (!id || !name)
      return res
        .status(400)
        .json({ error: "id and name are required" });

    await db.none(
      `INSERT INTO phases (id, name) VALUES ($1, $2)`,
      [id, name]
    );
    res.status(201).json({ id, name });
  } catch (e) {
    next(e);
  }
});

app.put("/phases/:id", async (req, res, next) => {
  try {
    const { name } = req.body;
    if (!name)
      return res.status(400).json({ error: "name is required" });

    const result = await db.result(
      `UPDATE phases SET name=$1 WHERE id=$2`,
      [name, req.params.id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Phase not found" });

    res.json({ id: req.params.id, name });
  } catch (e) {
    next(e);
  }
});

app.delete("/phases/:id", async (req, res, next) => {
  try {
    const result = await db.result(
      `DELETE FROM phases WHERE id=$1`,
      req.params.id
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Phase not found" });
    res.status(204).send();
  } catch (e) {
    next(e);
  }
});

/* ============================
   PHASE LOGS + LIVE STATUS
   ============================ */

app.get("/phase_logs", async (req, res, next) => {
  try {
    const rows = await db.any(
      `
      SELECT *
      FROM phase_logs
      ORDER BY start_time DESC
      LIMIT 500
    `
    );
    res.json(rows);
  } catch (e) {
    next(e);
  }
});

app.post("/phase_logs/start", async (req, res, next) => {
  try {
    const {
      operatorUsername,
      orderNumber,
      productionSheetNumber,
      productId,
      phaseId,
      totalQuantity,
      setupTime = 0,
      findMaterialTime = 0,
    } = req.body;

    const id = randomUUID();
    await db.none(
      `
      INSERT INTO phase_logs
      (id, operator_username, order_number, production_sheet_number, product_id, phase_id, start_time, total_quantity, setup_time, find_material_time)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9)
    `,
      [
        id,
        operatorUsername,
        orderNumber,
        productionSheetNumber,
        productId,
        phaseId,
        totalQuantity,
        setupTime,
        findMaterialTime,
      ]
    );

    const created = await db.one(
      `SELECT * FROM phase_logs WHERE id=$1`,
      id
    );
    res.status(201).json(created);
  } catch (e) {
    next(e);
  }
});

app.post("/phase_logs/finish/:id", async (req, res, next) => {
  try {
    const { endTime, quantityDone, productionTime = 0 } = req.body;
    const result = await db.result(
      `
      UPDATE phase_logs
      SET end_time=$1, quantity_done=$2, production_time=$3
      WHERE id=$4
    `,
      [endTime || new Date().toISOString(), quantityDone, productionTime, req.params.id]
    );
    if (result.rowCount === 0)
      return res.status(404).json({ error: "Phase log not found" });

    const updated = await db.one(
      `SELECT * FROM phase_logs WHERE id=$1`,
      req.params.id
    );
    res.json(updated);
  } catch (e) {
    next(e);
  }
});

app.post("/api/live/start", async (req, res, next) => {
  try {
    console.log("🔥 LIVE START CALLED:", req.body);
    const { username, sheetId, productId, phaseId, plannedTime, status } =
      req.body;

    await db.tx(async (t) => {
      await t.none(
        `
        UPDATE live_phase_log
        SET end_time = NOW()
        WHERE username = $1 AND end_time IS NULL
      `,
        [username]
      );

      await t.none(
        `
        INSERT INTO live_phase_log
        (id, username, sheet_id, product_id, phase_id, planned_time, start_time, status)
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
      `,
        [
          randomUUID(),
          username,
          sheetId,
          productId,
          phaseId,
          plannedTime,
          status || null,
        ]
      );
    });

    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

app.post("/api/live/stop", async (req, res, next) => {
  try {
    console.log("🛑 LIVE STOP CALLED:", req.body);
    const { username } = req.body;

    await db.none(
      `
      UPDATE live_phase_log
      SET end_time = NOW()
      WHERE username = $1 AND end_time IS NULL
    `,
      [username]
    );

    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

app.get("/api/live/status", async (req, res, next) => {
  try {
    const active = await db.any(
      `
      SELECT 
        l.username,
        l.sheet_id,
        ps.production_sheet_number,
        l.product_id,
        l.phase_id,
        l.planned_time,
        l.status,
        EXTRACT(EPOCH FROM (NOW() - l.start_time))::int AS running_seconds,
        CASE 
          WHEN EXTRACT(EPOCH FROM (NOW() - l.start_time)) > (l.planned_time * 60 * 1.05)
          THEN true ELSE false
        END AS is_overrun
      FROM live_phase_log l
      LEFT JOIN production_sheets ps ON ps.id = l.sheet_id
      WHERE l.end_time IS NULL
    `
    );

    const idle = await db.any(
      `
      SELECT 
        t.username,
        t.sheet_id          AS last_sheet_id,
        ps.production_sheet_number AS last_sheet_number,
        t.phase_id          AS last_phase_id,
        t.end_time          AS finished_at,
        EXTRACT(EPOCH FROM (NOW() - t.end_time))::int AS idle_seconds
      FROM live_phase_log t
      LEFT JOIN production_sheets ps ON ps.id = t.sheet_id
      WHERE t.end_time = (
        SELECT MAX(end_time)
        FROM live_phase_log
        WHERE username = t.username
      )
      AND t.username NOT IN (
        SELECT username FROM live_phase_log WHERE end_time IS NULL
      )
    `
    );

    res.json({ active, idle });
  } catch (e) {
    next(e);
  }
});

/* ============================
   PDF PARSE ENDPOINT
   ============================ */

function customPageRender(pageData) {
  return pageData.getTextContent().then((textContent) => {
    const items = textContent.items || [];
    const lines = [];

    let currentLine = [];
    let lastY = null;
    let lastXEnd = null;

    for (const item of items) {
      const str = (item.str || "").trim();
      if (!str) continue;

      const [a, b, c, d, x, y] = item.transform;
      const width = item.width || 0;

      if (lastY === null) {
        lastY = y;
        lastXEnd = x + width;
        currentLine.push(str);
        continue;
      }

      const deltaY = Math.abs(y - lastY);
      if (deltaY > 2) {
        if (currentLine.length) {
          lines.push(currentLine.join(" "));
        }
        currentLine = [str];
        lastY = y;
        lastXEnd = x + width;
        continue;
      }

      const gapX = x - lastXEnd;

      if (gapX > 1) {
        currentLine.push(str);
      } else {
        const lastIdx = currentLine.length - 1;
        currentLine[lastIdx] = (currentLine[lastIdx] || "") + str;
      }

      lastY = y;
      lastXEnd = x + width;
    }

    if (currentLine.length) {
      lines.push(currentLine.join(" "));
    }

    return lines.join("\n");
  });
}

app.post(
  "/parse_order_pdf",
  upload.single("file"),
  async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded" });
      }

      const data = await pdfParse(req.file.buffer, {
        pagerender: customPageRender,
      });

      console.log("======= RAW PDF TEXT =======");
      console.log(data.text);
      console.log("======= END PDF TEXT =======");

      const parsed = parseOrderPdfText(data.text || "");

      res.json(parsed);
    } catch (e) {
      console.error("❌ Failed to parse order PDF:", e);
      res
        .status(500)
        .json({ error: e.message || "Failed to parse PDF" });
    }
  }
);

/* ============================
   START SERVER
   ============================ */

initDB()
  .then(() => {
	app.listen(PORT, "0.0.0.0", () => {
	  console.log(`✅ API running on port ${PORT}`);
	});
  })
  .catch((err) => {
    console.error("❌ Failed to initialize database:", err);
    process.exit(1);
  });

/* ============================
   404 + ERROR HANDLERS
   ============================ */

app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err, req, res, next) => {
  console.error("💥 Server error:", err);
  res
    .status(500)
    .json({ error: err.message || "Internal server error" });
});
