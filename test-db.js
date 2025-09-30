import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';

// Explicitly resolve full path to your .env file
const envPath = path.resolve('C:/feven/luminar-backend/.env');

// Load environment variables
const result = dotenv.config({ path: envPath });

if (result.error) {
  console.error('❌ Failed to load .env file:', result.error);
  process.exit(1);
}

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI || !MONGODB_URI.includes('mongodb.net')) {
  console.error(
    '❌ Error: MONGODB_URI is not defined or does not appear to be an Atlas URI.'
  );
  process.exit(1);
}

console.log('🔹 Connecting to MongoDB Atlas...');

mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ Connected to MongoDB Atlas successfully!\n');

    const db = mongoose.connection.db;
    const collections = await db.listCollections().toArray();

    if (collections.length === 0) {
      console.log('No collections found in the database.');
    } else {
      console.log('📂 Collections and document counts:');
      for (const coll of collections) {
        const count = await db.collection(coll.name).countDocuments();
        console.log(`- ${coll.name}: ${count} document(s)`);
      }
    }

    await mongoose.connection.close();
    console.log('\n🏁 Connection closed. Done.');
    process.exit(0);
  })
  .catch(err => {
    console.error('❌ Failed to connect to MongoDB Atlas.');
    console.error('Detailed Error:', err.message);
    process.exit(1);
  });
