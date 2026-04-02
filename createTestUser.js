/**
 * Create Test User Script
 * Adds a test user to MongoDB for testing password reset
 */

require("dotenv").config();
const mongoose = require("mongoose");
const User = require("./models/User");
const bcrypt = require("bcryptjs");

async function createTestUser() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    console.log("✅ Connected to MongoDB");

    // Check if user already exists
    const existingUser = await User.findOne({
      email: "sakthisivaram62@gmail.com",
    });

    if (existingUser) {
      console.log("ℹ️  User already exists in database");
      await mongoose.disconnect();
      process.exit(0);
    }

    // Create new user
    const newUser = new User({
      email: "sakthisivaram62@gmail.com",
      password: "TestPassword123!@#", // Dummy password (will be hashed)
      name: "Test User",
    });

    // Save user (password will be hashed by pre-hook)
    await newUser.save();

    console.log("✅ Test user created successfully!");
    console.log(`   Email: sakthisivaram62@gmail.com`);
    console.log(`   Password: TestPassword123!@#`);

    await mongoose.disconnect();
    process.exit(0);
  } catch (error) {
    console.error("❌ Error creating user:", error.message);
    process.exit(1);
  }
}

createTestUser();
