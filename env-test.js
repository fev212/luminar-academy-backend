import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

// Resolve current folder
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ✅ Step A: Read raw file
const envPath = path.resolve(__dirname, '.env');
console.log("Looking for .env file at:", envPath);

if (fs.existsSync(envPath)) {
  const raw = fs.readFileSync(envPath, 'utf8');
  console.log("\n📄 Raw .env file content:\n", raw);
} else {
  console.error("❌ No .env file found at:", envPath);
}

// ✅ Step B: Load with dotenv
const result = dotenv.config({ path: envPath });
if (result.error) {
  console.error("❌ dotenv failed:", result.error);
} else {
  console.log("\n✅ dotenv parsed values:", result.parsed);
}

// ✅ Step C: Show Node.js env
console.log("\n🔹 process.env.MONGODB_URI =", process.env.MONGODB_URI);
