/**
 * TaskMaster API — Node.js + Express Backend
 * ============================================
 * In-memory data store (no DB setup needed for demo).
 * Swap `users` and `tasks` arrays with a real DB (MongoDB/PostgreSQL) in production.
 *
 * Run:  node server.js
 * API:  http://localhost:5000/api
 */

const express = require("express");
const crypto = require("crypto"); // built-in Node module — no install needed
const app = express();
const PORT = 5000;

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

app.use(express.json()); // parse JSON request bodies

// Manual CORS middleware (no external package needed)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ─── IN-MEMORY DATA STORE ────────────────────────────────────────────────────
// In production: replace with MongoDB (mongoose) or PostgreSQL (pg/prisma)

const users = []; // { id, name, email, passwordHash }
const tasks = []; // { id, userId, title, description, priority, dueDate, status, createdAt }

// ─── HELPERS ─────────────────────────────────────────────────────────────────

/** Generate a simple unique ID */
function generateId() {
  return crypto.randomBytes(8).toString("hex");
}

/** Hash a password using Node's built-in crypto (SHA-256 + salt) */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.createHmac("sha256", salt).update(password).digest("hex");
  return `${salt}:${hash}`;
}

/** Compare plain password against stored hash */
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const attempt = crypto.createHmac("sha256", salt).update(password).digest("hex");
  return attempt === hash;
}

/** Sign a simple JWT-like token (Base64 encoded, HMAC signed) */
const SECRET = "taskmaster_secret_key_2026"; // in production: use env variable

function signToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SECRET).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  try {
    const [header, body, sig] = token.split(".");
    const expected = crypto.createHmac("sha256", SECRET).update(`${header}.${body}`).digest("base64url");
    if (sig !== expected) return null;
    return JSON.parse(Buffer.from(body, "base64url").toString());
  } catch {
    return null;
  }
}

/** Middleware: protect routes — require valid token */
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization; // "Bearer <token>"
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided. Please log in." });
  }
  const token = authHeader.split(" ")[1];
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
  req.userId = payload.userId; // attach userId to every protected request
  next();
}

/** Determine task status: pending / completed / overdue */
function getTaskStatus(task) {
  if (task.status === "completed") return "completed";
  if (task.dueDate && new Date(task.dueDate) < new Date()) return "overdue";
  return "pending";
}

/** Check if a task is due within the next 24 hours */
function isDueSoon(task) {
  if (task.status === "completed" || !task.dueDate) return false;
  const now = new Date();
  const due = new Date(task.dueDate);
  const hoursUntilDue = (due - now) / (1000 * 60 * 60);
  return hoursUntilDue > 0 && hoursUntilDue <= 24;
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

/**
 * POST /api/auth/register
 * Body: { name, email, password }
 * Creates a new user account
 */
app.post("/api/auth/register", (req, res) => {
  const { name, email, password } = req.body;

  // Validate input
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Name, email, and password are required." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters." });
  }

  // Check if email already exists
  const existing = users.find((u) => u.email === email.toLowerCase());
  if (existing) {
    return res.status(409).json({ error: "An account with this email already exists." });
  }

  // Create user
  const user = {
    id: generateId(),
    name: name.trim(),
    email: email.toLowerCase().trim(),
    passwordHash: hashPassword(password),
    createdAt: new Date().toISOString(),
  };
  users.push(user);

  // Return token immediately (auto-login after register)
  const token = signToken({ userId: user.id });
  res.status(201).json({
    message: "Account created successfully.",
    token,
    user: { id: user.id, name: user.name, email: user.email },
  });
});

/**
 * POST /api/auth/login
 * Body: { email, password }
 * Returns a token on success
 */
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required." });
  }

  const user = users.find((u) => u.email === email.toLowerCase());
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: "Invalid email or password." });
  }

  const token = signToken({ userId: user.id });
  res.json({
    message: "Login successful.",
    token,
    user: { id: user.id, name: user.name, email: user.email },
  });
});

// ─── TASK ROUTES (all protected) ─────────────────────────────────────────────

/**
 * GET /api/tasks
 * Returns all tasks for the logged-in user
 * Query params: ?status=pending|completed|overdue  ?priority=high|medium|low  ?sort=dueDate|priority|createdAt
 */
app.get("/api/tasks", authenticate, (req, res) => {
  const { status, priority, sort } = req.query;

  // Get only THIS user's tasks — key security requirement
  let userTasks = tasks
    .filter((t) => t.userId === req.userId)
    .map((t) => ({ ...t, status: getTaskStatus(t), dueSoon: isDueSoon(t) }));

  // Filter by status
  if (status) {
    userTasks = userTasks.filter((t) => t.status === status);
  }

  // Filter by priority
  if (priority) {
    userTasks = userTasks.filter((t) => t.priority === priority);
  }

  // Sort
  if (sort === "dueDate") {
    userTasks.sort((a, b) => new Date(a.dueDate || 0) - new Date(b.dueDate || 0));
  } else if (sort === "priority") {
    const order = { high: 0, medium: 1, low: 2 };
    userTasks.sort((a, b) => (order[a.priority] ?? 3) - (order[b.priority] ?? 3));
  } else {
    // Default: newest first
    userTasks.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }

  res.json({ tasks: userTasks, count: userTasks.length });
});

/**
 * POST /api/tasks
 * Body: { title, description, priority, dueDate }
 * Creates a new task
 */
app.post("/api/tasks", authenticate, (req, res) => {
  const { title, description, priority, dueDate } = req.body;

  if (!title || title.trim() === "") {
    return res.status(400).json({ error: "Task title is required." });
  }

  const validPriorities = ["high", "medium", "low"];
  if (priority && !validPriorities.includes(priority)) {
    return res.status(400).json({ error: "Priority must be high, medium, or low." });
  }

  const task = {
    id: generateId(),
    userId: req.userId, // link task to logged-in user
    title: title.trim(),
    description: description?.trim() || "",
    priority: priority || "medium",
    dueDate: dueDate || null,
    status: "pending",
    createdAt: new Date().toISOString(),
    completedAt: null,
  };

  tasks.push(task);
  res.status(201).json({ message: "Task created.", task: { ...task, status: getTaskStatus(task) } });
});

/**
 * PUT /api/tasks/:id
 * Body: { title, description, priority, dueDate }
 * Update a task's details
 */
app.put("/api/tasks/:id", authenticate, (req, res) => {
  const task = tasks.find((t) => t.id === req.params.id && t.userId === req.userId);
  if (!task) return res.status(404).json({ error: "Task not found." });

  const { title, description, priority, dueDate } = req.body;
  if (title !== undefined) task.title = title.trim();
  if (description !== undefined) task.description = description.trim();
  if (priority !== undefined) task.priority = priority;
  if (dueDate !== undefined) task.dueDate = dueDate;

  res.json({ message: "Task updated.", task: { ...task, status: getTaskStatus(task) } });
});

/**
 * PATCH /api/tasks/:id/complete
 * Marks a task as completed
 */
app.patch("/api/tasks/:id/complete", authenticate, (req, res) => {
  const task = tasks.find((t) => t.id === req.params.id && t.userId === req.userId);
  if (!task) return res.status(404).json({ error: "Task not found." });

  task.status = "completed";
  task.completedAt = new Date().toISOString();
  res.json({ message: "Task marked as complete! 🎉", task });
});

/**
 * DELETE /api/tasks/:id
 * Deletes a task
 */
app.delete("/api/tasks/:id", authenticate, (req, res) => {
  const index = tasks.findIndex((t) => t.id === req.params.id && t.userId === req.userId);
  if (index === -1) return res.status(404).json({ error: "Task not found." });

  tasks.splice(index, 1);
  res.json({ message: "Task deleted." });
});

// ─── DASHBOARD ROUTE ─────────────────────────────────────────────────────────

/**
 * GET /api/dashboard
 * Returns productivity summary for the logged-in user
 */
app.get("/api/dashboard", authenticate, (req, res) => {
  const userTasks = tasks.filter((t) => t.userId === req.userId);

  const enriched = userTasks.map((t) => ({ ...t, computedStatus: getTaskStatus(t) }));

  const total = enriched.length;
  const completed = enriched.filter((t) => t.computedStatus === "completed").length;
  const pending = enriched.filter((t) => t.computedStatus === "pending").length;
  const overdue = enriched.filter((t) => t.computedStatus === "overdue").length;
  const dueSoon = enriched.filter((t) => isDueSoon(t)).length;
  const completionRate = total > 0 ? Math.round((completed / total) * 100) : 0;

  // Priority breakdown
  const byPriority = {
    high: enriched.filter((t) => t.priority === "high" && t.computedStatus !== "completed").length,
    medium: enriched.filter((t) => t.priority === "medium" && t.computedStatus !== "completed").length,
    low: enriched.filter((t) => t.priority === "low" && t.computedStatus !== "completed").length,
  };

  // Top 3 urgent tasks (overdue or high priority, not completed)
  const urgent = enriched
    .filter((t) => t.computedStatus !== "completed" && (t.computedStatus === "overdue" || t.priority === "high"))
    .sort((a, b) => new Date(a.dueDate || 0) - new Date(b.dueDate || 0))
    .slice(0, 3)
    .map(({ userId, ...rest }) => rest); // strip userId from response

  res.json({
    summary: { total, completed, pending, overdue, dueSoon, completionRate },
    byPriority,
    urgentTasks: urgent,
  });
});

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "TaskMaster API is running!", time: new Date().toISOString() });
});

// ─── START SERVER ─────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🚀 TaskMaster API running at http://localhost:${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health\n`);
});

module.exports = app;
