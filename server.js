/**
 * Main Express Server
 * Password Reset Flow API with Email Verification
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const connectDB = require("./utils/database");
const { errorHandler } = require("./middleware/auth");
const authRoutes = require("./routes/auth");

const app = express();

// ============================================================================
// MIDDLEWARE SETUP
// ============================================================================

// Security middleware
app.use(helmet());

// CORS configuration
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  })
);

// Body parsing
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

// ============================================================================
// CONNECT TO DATABASE
// ============================================================================

connectDB().catch((error) => {
  console.error("Failed to connect to database:", error);
  process.exit(1);
});

// ============================================================================
// API ROUTES
// ============================================================================

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Server is running",
    timestamp: new Date().toISOString(),
  });
});

// Authentication routes
app.use("/api/auth", authRoutes);

// ============================================================================
// 404 HANDLER
// ============================================================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found",
  });
});

// ============================================================================
// ERROR HANDLER (must be last)
// ============================================================================

app.use(errorHandler);

// ============================================================================
// SERVER STARTUP
// ============================================================================

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║   Password Reset API Server                                ║
║   Environment: ${process.env.NODE_ENV || "development"}                               ║
║   Port: ${PORT}                                                    ║
║   Status: ✅ Running                                        ║
╚════════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM signal received: closing HTTP server");
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("SIGINT signal received: closing HTTP server");
  server.close(() => {
    console.log("HTTP server closed");
    process.exit(0);
  });
});

// Unhandled promise rejection
process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err);
  server.close(() => {
    process.exit(1);
  });
});

module.exports = app;
