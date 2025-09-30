// c:\feven\luminar-backend\server.js
import { nanoid } from 'nanoid';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit'; // celebrate is used in a different block, so it's not removed
import { celebrate, Joi, Segments, errors as celebrateErrors } from 'celebrate';
import nodemailer from 'nodemailer';
import compression from 'compression';
import multer from 'multer';
import morgan from 'morgan';
import cron from 'node-cron';
import fs from 'fs';
import path from 'path';
import PDFDocument from 'pdfkit';

dotenv.config();

// --- Config ---
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);
const CORS_ORIGIN = process.env.CORS_ORIGIN || true;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/luminar_academy';
const IS_PROD = process.env.NODE_ENV === 'production';

app.use(cors({ origin: IS_PROD ? CORS_ORIGIN : true, credentials: true }));
app.use(helmet({
    contentSecurityPolicy: false
}));

// --- HTTPS Redirect Middleware (Production Only) ---
if (IS_PROD) {
    app.use((req, res, next) => {
        // The 'x-forwarded-proto' header is set by proxies like Heroku, AWS ELB, etc.
        if (req.headers['x-forwarded-proto'] !== 'https') {
            return res.redirect('https://' + req.get('host') + req.url);
        }
        next();
    });
}

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
app.use(limiter);
app.use(compression());

// --- Directory Setup for Uploads ---
// Ensure that the directories for file uploads exist before the server starts.
const uploadsDir = path.join(process.cwd(), 'uploads');
const videosDir = path.join(uploadsDir, 'videos');
const documentsDir = path.join(uploadsDir, 'documents');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
if (!fs.existsSync(videosDir)) fs.mkdirSync(videosDir);
if (!fs.existsSync(documentsDir)) fs.mkdirSync(documentsDir);

// --- File Uploads (Multer) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // In a real app, you'd want to ensure this directory exists
        // Separate files by type
        if (file.mimetype.startsWith('video/')) {
            cb(null, 'uploads/videos/');
        } else {
            cb(null, 'uploads/documents/');
        }
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + '.' + file.originalname.split('.').pop());
    }
});
// Configure multer to handle a single optional file upload named 'mediaFile'.
const upload = multer({ storage: storage });

// --- Middleware Order Correction ---
// JSON and cookie parsers should come after multer is configured for specific routes,
// but for simplicity in this app structure, we can apply them globally before routes.
// The key is that routes using `upload` will correctly parse multipart/form-data first.
app.use(morgan('combined'));
app.use(express.json());
app.use(cookieParser());

// Serve static files from both videos and documents directories
app.use('/uploads/videos', express.static('uploads/videos'));
app.use('/uploads/documents', express.static('uploads/documents'));

// --- DB ---
export async function connectDB() {
    try {
        // The dbName should ideally be part of the MONGODB_URI.
        // This approach is more flexible and standard for Atlas connections.
        // Your local fallback URI already includes it: '.../luminar_academy'
        // Ensure your production MONGO_URI also includes the database name.
        await mongoose.connect(MONGODB_URI);
        console.log('MongoDB connected successfully');
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
}

export async function closeDB() {
    await mongoose.connection.close();
}


// --- Schemas/Models ---
const UserSchema = new mongoose.Schema({
    role: { type: String, default: 'user' },
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    schoolName: { type: String },
    passwordHash: { type: String, required: true },
    verified: { type: Boolean, default: false },
    paymentStatus: { type: String, default: 'none' }, // Explicitly set default status
    createdAt: { type: Date, default: Date.now },
    plan: { type: String }, // Add plan to the user schema
    stream: { type: String },
    progress: [{
        subject: String,
        grade: Number,
        unit: Number,
        percentage: Number,
        status: String
    }],
    quizResults: [{
        subject: String,
        grade: Number,
        unit: Number,
        score: Number,
        passed: Boolean,
        date: { type: Date, default: Date.now }
    }],
    activities: [{ type: mongoose.Schema.Types.Mixed }],
    schedule: {
        days: [String],
        times: [String],
        duration: Number,
        notifications: { email: Boolean }
    },
    resetPasswordToken: { type: String },
    resetPasswordExpiresAt: { type: Date },
    certificateId: { type: String, unique: true, sparse: true }
});
const User = mongoose.model('User', UserSchema);

const PaymentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    plan: { type: String, enum: ['basic', 'advanced'] },
    paymentMethod: String,
    accountName: String,
    accountNumber: String,
    transactionId: String,
    notes: String,
    amount: String,
    status: { type: String, default: 'pending' },
    paymentDate: { type: Date, default: Date.now }
});
const Payment = mongoose.model('Payment', PaymentSchema);

const CourseContentSchema = new mongoose.Schema({
    subject: { type: String, required: true },
    grade: { type: Number, required: true },
    unit: { type: Number, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    videoUrl: { type: String },
});
// Add index for faster course content lookups
CourseContentSchema.index({ subject: 1, grade: 1 });
const CourseContent = mongoose.model('CourseContent', CourseContentSchema);

const QuizQuestionSchema = new mongoose.Schema({
    subject: { type: String, required: true },
    grade: { type: Number, required: true },
    unit: { type: Number, required: true },
    question: { type: String, required: true },
    stream: { type: String },
    options: { type: [String], required: true },
    answer: { type: Number, required: true }, // 0-indexed
    explanation: { type: String }
});
// Add index for faster quiz question lookups
QuizQuestionSchema.index({ subject: 1, grade: 1 });
const QuizQuestion = mongoose.model('QuizQuestion', QuizQuestionSchema);

// Generic key-value storage (to mirror localStorage seamlessly)
const KVSchema = new mongoose.Schema({ key: { type: String, unique: true }, data: mongoose.Schema.Types.Mixed });
const KV = mongoose.model('KV', KVSchema);

// --- Auth helpers ---
function signToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function signRefreshToken(payload) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
}

function auth(req, res, next) {
    const header = req.headers.authorization;
    const token = header && header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Unauthorized' });
    }
}

function adminOnly(req, res, next) {
    if (req.user && req.user.role === 'admin') return next();
    return res.status(403).json({ error: 'Forbidden' });
}

function optionalAuth(req, res, next) {
    const header = req.headers.authorization;
    const token = header && header.startsWith('Bearer ') ? header.slice(7) : null;
    if (token) {
        try {
            req.user = jwt.verify(token, JWT_SECRET);
        } catch {
            req.user = null;
        }
    }
    next();
}

// --- Seed admin ---
async function seedAdmin() {
    const adminEmail = 'admin@luminarschool.com';
    const adminPassword = 'admin123';
    const passwordHash = bcrypt.hashSync(adminPassword, BCRYPT_ROUNDS);

    // Use findOneAndUpdate with upsert to either create or update the admin user
    await User.findOneAndUpdate(
        { email: adminEmail },
        {
            $set: {
                role: 'admin',
                fullName: 'Site Admin',
                schoolName: 'N/A',
                passwordHash: passwordHash,
                verified: true
            }
        },
        { upsert: true, new: true } // upsert: create if not found; new: return updated doc
    );
    console.log(`Admin user '${adminEmail}' ensured to be up to date.`);

    const settings = await KV.findOne({ key: 'public_settings' });
    if (!settings) {
        await KV.create({ key: 'public_settings', data: { advancedPlanEnabled: true } });
        console.log('Public settings seeded');
    }

    // Seed some sample content for testing if it doesn't exist
    const sampleContent = await CourseContent.findOne({ subject: 'physics', grade: 9, unit: 1 });
    if (!sampleContent) {
        await CourseContent.create({
            subject: 'physics',
            grade: 9,
            unit: 1,
            title: 'Introduction to Mechanics',
            content: `
                <p>Mechanics is the branch of physics concerned with the behavior of physical bodies when subjected to forces or displacements, and the subsequent effects of the bodies on their environment.</p>
                <h4>Key Concepts:</h4>
                <ul><li><strong>Kinematics:</strong> The study of motion without considering its causes.</li><li><strong>Dynamics:</strong> The study of motion and its causes (forces).</li><li><strong>Statics:</strong> The study of forces on objects at rest.</li></ul>
            `
        });
        console.log('Sample course content seeded.');
    }

    const sampleChemContent = await CourseContent.findOne({ subject: 'chemistry', grade: 9, unit: 1 });
    if (!sampleChemContent) {
        await CourseContent.create({
            subject: 'chemistry',
            grade: 9,
            unit: 1,
            title: 'The Structure of the Atom',
            content: `
                <p>The atom is the smallest unit of ordinary matter that forms a chemical element. Every solid, liquid, gas, and plasma is composed of neutral or ionized atoms.</p>
                <h4>Key Components:</h4>
                <ul><li><strong>Protons:</strong> Positively charged particles in the nucleus.</li><li><strong>Neutrons:</strong> Neutral particles in the nucleus.</li><li><strong>Electrons:</strong> Negatively charged particles orbiting the nucleus.</li></ul>
            `
        });
        console.log('Sample chemistry content seeded.');
    }
}

// --- Mailer (using environment or ethereal fallback) ---
let transporter;
async function setupMailer() {
    if (process.env.SMTP_HOST) {
        console.log('Using SMTP for email transport.');
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: Number(process.env.SMTP_PORT || 587),
            secure: false,
            auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        });
    } else {
        console.log('No SMTP config found. Using Ethereal for email transport.');
        try {
            const account = await nodemailer.createTestAccount();
            console.log('Ethereal test account created. Mail will be sent there.');
            console.log('Credentials:', account.user, account.pass);
            transporter = nodemailer.createTransport({
                host: 'smtp.ethereal.email',
                port: 587,
                secure: false,
                auth: { user: account.user, pass: account.pass }
            });
        } catch (err) {
            console.error('Failed to create an Ethereal test account. Using JSON transport as a fallback.', err);
            transporter = nodemailer.createTransport({ jsonTransport: true });
        }
    }
}

// --- Scheduled Tasks (Cron Jobs) ---

// This cron job runs at the start of each study block (6am, 12pm, 6pm, 10pm)
// to send a single, timely reminder to users.
// '0 6,12,18,22 * * *' means: at minute 0 of hours 6, 12, 18, and 22, every day.
cron.schedule('0 6,12,18,22 * * *', async () => {
    console.log('Running scheduled task: Checking for study reminders...');

    const now = new Date();
    const dayOfWeek = now.toLocaleString('en-US', { weekday: 'long' }).toLowerCase(); // e.g., 'monday'
    const hour = now.getHours(); // 0-23

    // Determine the current time slot based on the schedule.html page
    let timeSlot;
    if (hour >= 6 && hour < 12) timeSlot = 'morning';
    else if (hour >= 12 && hour < 18) timeSlot = 'afternoon';
    else if (hour >= 18 && hour < 22) timeSlot = 'evening';
    else if (hour >= 22 || hour < 6) timeSlot = 'night';

    if (!timeSlot) {
        console.log('Not within a defined study time slot. Skipping reminder check.');
        return;
    }

    try {
        // Find all users who have a schedule for the current day and time slot, and have email notifications enabled.
        const usersToNotify = await User.find({
            'schedule.days': dayOfWeek,
            'schedule.times': timeSlot,
            'schedule.notifications.email': true
        }).lean();

        if (usersToNotify.length === 0) {
            console.log('No users to notify at this time.');
            return;
        }

        console.log(`Found ${usersToNotify.length} user(s) to notify.`);
        for (const user of usersToNotify) {
            await transporter.sendMail({ to: user.email, subject: 'Study Reminder - Luminar School', text: `Hi ${user.fullName},\n\nThis is your friendly reminder that it's time for your scheduled study session!\n\nHappy learning!\n\nThe Luminar School Team` });
            console.log(`Study reminder sent to ${user.email}`);
        }
    } catch (error) {
        console.error('Error sending study reminders:', error);
    }
});

// --- Routes ---
app.get('/api/health', (req, res) => res.json({ ok: true }));
app.get('/api/ready', async (req, res) => {
    const state = mongoose.connection.readyState;
    if (state === 1) return res.json({ ready: true });
    return res.status(503).json({ ready: false });
});

app.get('/api/settings/public', async (req, res) => {
    const settings = await KV.findOne({ key: 'public_settings' }).lean();
    // Ensure we always return a settings object, even if it's not in the DB
    res.json({ ok: true, settings: settings ? settings.data : { advancedPlanEnabled: false } });
});

// Storage mirror (non-breaking with existing frontend)
app.get('/api/storage/:key', async (req, res) => {
    const kv = await KV.findOne({ key: req.params.key }).lean();
    res.json({ data: kv ? kv.data : null });
});

app.post('/api/storage/:key', async (req, res) => {
    const { key } = req.params;
    const { data } = req.body;
    await KV.updateOne({ key }, { key, data }, { upsert: true });
    res.json({ ok: true });
});

// Auth
app.post(
    '/api/register',
    celebrate({
        [Segments.BODY]: Joi.object({
            fullName: Joi.string().min(2).max(100).required(),
            email: Joi.string().email().required(),
            schoolName: Joi.string().min(2).max(120).required(),
            password: Joi.string().min(6).max(128).required()
        })
    }),
    async (req, res, next) => {
    const { fullName, email, schoolName, password } = req.body;
    try {
        const exists = await User.findOne({ email });
        if (exists) return res.status(409).json({ error: 'Email already registered' });

        // Use async bcrypt to avoid blocking the event loop under load
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const emailVerificationToken = nanoid(32);

        const user = await User.create({ fullName, email, schoolName, passwordHash, role: 'user', verified: false, emailVerificationToken });
        
        // Send verification email (fire-and-forget, no need to await)
        const verifyLink = `${process.env.APP_ORIGIN || 'http://localhost:' + PORT}/verify-email?token=${emailVerificationToken}`;
        transporter.sendMail({
            to: email,
            subject: 'Verify your email',
            text: `Click to verify your email: ${verifyLink}`
        }).catch(err => console.error(`Failed to send verification email to ${email}:`, err));

        const token = signToken({ id: user._id.toString(), role: user.role });
        res.json({ ok: true, token, user: { id: user._id, fullName, email, schoolName, verified: user.verified, role: user.role } });
    } catch (error) {
        // Handle race condition where two users sign up with the same email at once
        if (error.code === 11000) { // MongoDB duplicate key error
            return res.status(409).json({ error: 'Email already registered' });
        }
        // Pass other errors to the global error handler
        next(error);
    }
}
);

app.post(
    '/api/login',
    celebrate({
        [Segments.BODY]: Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().min(6).max(128).required()
        })
    }),
    async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = signToken({ id: user._id.toString(), role: user.role });
    const refresh = signRefreshToken({ id: user._id.toString(), role: user.role });
    res.cookie('refreshToken', refresh, { httpOnly: true, sameSite: 'lax', secure: IS_PROD, maxAge: 30 * 24 * 3600 * 1000 });
    res.json({ ok: true, token, user: { id: user._id, fullName: user.fullName, email: user.email, schoolName: user.schoolName, verified: user.verified, role: user.role } });
}
);

// Email verification
app.get('/api/auth/verify-email', async (req, res) => {
    const { token } = req.query;
    const user = await User.findOne({ emailVerificationToken: token });
    if (!user) return res.status(400).json({ error: 'Invalid token' });
    user.verified = true;
    user.emailVerificationToken = undefined;
    await user.save();
    res.json({ ok: true });
});

// Password reset request
app.post(
    '/api/auth/request-reset', celebrate({ [Segments.BODY]: Joi.object({ email: Joi.string().email().required() }) }),
    async (req, res) => {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.json({ ok: true });
        user.resetPasswordToken = nanoid(32);
        user.resetPasswordExpiresAt = new Date(Date.now() + 3600 * 1000);
        await user.save();
        const link = `${process.env.APP_ORIGIN || 'http://localhost:' + PORT}/reset-password?token=${user.resetPasswordToken}`;
        const info = await transporter.sendMail({ to: email, subject: 'Reset your password', text: `Reset your password using this link: ${link}` });
        // Log Ethereal URL if in dev mode
        if (process.env.NODE_ENV !== 'production' && nodemailer.getTestMessageUrl(info)) console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
        res.json({ ok: true });
    }
);

// Password reset
app.post(
    '/api/auth/reset-password',
    celebrate({ [Segments.BODY]: Joi.object({ token: Joi.string().required(), password: Joi.string().min(6).max(128).required() }) }),
    async (req, res) => {
        const { token, password } = req.body;
        const user = await User.findOne({ resetPasswordToken: token, resetPasswordExpiresAt: { $gt: new Date() } });
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }
        // Use async bcrypt to avoid blocking the event loop
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        user.passwordHash = passwordHash;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpiresAt = undefined;
        await user.save();
        res.json({ ok: true });
    }
);

app.get('/api/me', auth, async (req, res) => {
    const user = await User.findById(req.user.id, { passwordHash: 0 }).lean();
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
    res.json({ ok: true, user });
});

app.post('/api/user/stream', auth, async (req, res) => {
    const { stream } = req.body;
    if (!['natural', 'social'].includes(stream)) {
        return res.status(400).json({ error: 'Invalid stream' });
    }
    await User.updateOne({ _id: req.user.id }, { $set: { stream } });
    res.json({ ok: true });
});

app.post('/api/schedule', auth, async (req, res) => {
    const { days, times, duration, notifications } = req.body;
    await User.updateOne({ _id: req.user.id }, { $set: { schedule: { days, times, duration, notifications } } });
    res.json({ ok: true });
});

app.post('/api/progress', auth, async (req, res) => {
    const { subject, grade, unit, percentage, status } = req.body;
    const progressUpdate = { subject, grade, unit, percentage, status };

    // Use a more robust pull/push pattern to prevent duplicate entries.
    // First, remove any existing progress record for this specific unit.
    await User.updateOne({ _id: req.user.id }, { $pull: { progress: { subject, grade, unit } } });
    // Then, add the new or updated progress record.
    await User.updateOne({ _id: req.user.id }, { $push: { progress: progressUpdate } });

    res.json({ ok: true });
});

app.post('/api/activity', auth, async (req, res) => {
    const activity = { ...req.body, createdAt: new Date() };
    await User.updateOne({ _id: req.user.id }, { $push: { activities: { $each: [activity], $slice: -20 } } });
    res.json({ ok: true });
});

app.post('/api/quiz-results', auth, async (req, res) => {
    const { subject, grade, unit, score, passed } = req.body;
    const result = { subject, grade, unit, score, passed, date: new Date() };
    await User.updateOne({ _id: req.user.id }, { $push: { quizResults: result } });

    // If the quiz was passed, also mark the unit as complete.
    if (passed) {
        const progressUpdate = { subject, grade, unit, percentage: 100, status: 'completed' };
        // This is an idempotent operation: remove any existing progress for this unit, then add the new 'completed' one.
        // This prevents duplicate entries and ensures the status is always correct.
        await User.updateOne({ _id: req.user.id }, { $pull: { progress: { subject, grade, unit } } });
        await User.updateOne({ _id: req.user.id }, { $push: { progress: progressUpdate } });

        // If this was the final exam, generate and save a unique certificate ID.
        if (subject === 'final') {
            const user = await User.findById(req.user.id);
            if (user && !user.certificateId) {
                user.certificateId = nanoid(24);
                await user.save();
                return res.json({ ok: true, certificateId: user.certificateId });
            }
        }
    }

    res.json({ ok: true });
});

app.get('/api/courses/:subject/:grade', optionalAuth, async (req, res) => {
    const { subject, grade } = req.params;
    const { unit } = req.query;    
    const query = { subject, grade: parseInt(grade, 10) };

    // If a user is logged in and approved, they get all content for the grade.
    if (req.user) {
        const user = await User.findById(req.user.id).lean();
        if (user && user.paymentStatus === 'approved') {
            // Security check: Ensure only users with an 'advanced' plan can access 'english_advanced' content.
            if (subject === 'english_advanced' && user.plan !== 'advanced') {
               return res.status(403).json({
                    ok: false,
                    error: 'Access denied. This content requires an Advanced Plan.'
                });
            }

            if (unit) query.unit = parseInt(unit, 10);
            const units = await CourseContent.find(query).sort({ unit: 1 }).lean();
            const questions = await QuizQuestion.find(query).lean();
            return res.json({ ok: true, units, questions });
        }
    }

    // Special handling for the final exam to fetch questions based on the user's stream.
    if (req.user && subject === 'final') {
        const user = await User.findById(req.user.id).lean();
        if (user && user.stream) {
            query.stream = user.stream;
        }
    }

    // For all other cases (trial users, guests, non-approved users), only serve Unit 1.
    query.unit = 1;
    const units = await CourseContent.find(query).sort({ unit: 1 }).lean();
    const questions = await QuizQuestion.find(query).lean();
    res.json({ ok: true, units, questions });
});

// Public certificate data endpoint
app.get('/api/certificate/view/:certificateId', async (req, res) => {
    const { certificateId } = req.params;
    if (!certificateId) {
        return res.status(400).json({ error: 'Certificate ID is required.' });
    }
    const user = await User.findOne({ certificateId }).lean();
    if (!user) {
        return res.status(404).json({ error: 'Certificate not found.' });
    }

    const finalExamResult = user.quizResults?.find(r => r.subject === 'final' && r.passed);
    res.json({ ok: true, fullName: user.fullName, completionDate: finalExamResult?.date });
});

// Certificate Generation
app.get('/api/certificate/download', auth, async (req, res) => {
    const user = await User.findById(req.user.id).lean();
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Security Check: Ensure the user has actually passed the final exam.
    const finalExamResult = user.quizResults?.find(r => r.subject === 'final' && r.passed);
    if (!finalExamResult) {
        return res.status(403).json({ error: 'You have not passed the final exam.' });
    }

    const doc = new PDFDocument({ size: 'A4', layout: 'landscape' });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=Luminar_School_Certificate_${user.fullName.replace(/ /g, '_')}.pdf`);

    doc.pipe(res);

    // Certificate Styling
    doc.rect(0, 0, doc.page.width, doc.page.height).fillColor('#f0f4ff').fill();
    doc.rect(20, 20, doc.page.width - 40, doc.page.height - 40).lineWidth(3).stroke('#667eea');

    // Content
    doc.fontSize(40).fillColor('#333').font('Helvetica-Bold').text('Certificate of Completion', { align: 'center', y: 80 });

    doc.fontSize(20).fillColor('#666').font('Helvetica').text('This is to certify that', { align: 'center', y: 180 });

    doc.fontSize(36).fillColor('#667eea').font('Helvetica-Bold').text(user.fullName, { align: 'center', y: 220 });

    doc.fontSize(20).fillColor('#666').font('Helvetica').text('has successfully completed the Luminar School preparatory course.', { align: 'center', y: 280 });

    const completionDate = new Date(finalExamResult.date).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    doc.fontSize(18).fillColor('#333').font('Helvetica').text(`Date of Completion: ${completionDate}`, { align: 'center', y: 350 });

    doc.fontSize(16).fillColor('#333').font('Helvetica').text('____________________', { align: 'center', y: 450 });
    doc.fontSize(14).fillColor('#666').font('Helvetica').text('Authorized Signature', { align: 'center', y: 470 });

    doc.end();
});

// Payments
app.post(
    '/api/payments',
    auth,
    celebrate({
        [Segments.BODY]: Joi.object({
            plan: Joi.string().valid('basic', 'advanced').required(),
            paymentMethod: Joi.string().valid('telebirr', 'cbe', 'awash').required(),
            accountName: Joi.string().min(2).max(120).required(),
            accountNumber: Joi.string().min(3).max(40).required(),
            transactionId: Joi.string().allow('', null),
            notes: Joi.string().allow('', null),
            amount: Joi.string().required()
        })
    }),
    async (req, res) => {
    const payment = await Payment.create({ userId: req.user.id, ...req.body, status: req.body.status || 'pending' });
    res.json({ ok: true, payment });
}
);

// Admin
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const users = await User.find({}, { passwordHash: 0 }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean();
    const total = await User.countDocuments();
    res.json({ users, total, page, pages: Math.ceil(total / limit) });
});

app.post('/api/admin/users/:id/verify', auth, adminOnly, async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) {
        return res.status(404).json({ error: 'Not found' });
    }
    user.verified = true;
    await user.save();
    res.json({ ok: true });
});

app.get('/api/admin/payments', auth, adminOnly, async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const payments = await Payment.find().sort({ paymentDate: -1 }).skip(skip).limit(limit).lean();
    const total = await Payment.countDocuments();
    res.json({ payments, total, page, pages: Math.ceil(total / limit) });
});

app.post('/api/admin/payments/:id/verify', auth, adminOnly, async (req, res) => {
    const payment = await Payment.findById(req.params.id);
    if (!payment) {
        return res.status(404).json({ error: 'Not found' });
    }

    // Update payment status
    payment.status = 'verified';
    await payment.save();

    // Update the corresponding user's paymentStatus to grant access
    await User.updateOne({ _id: payment.userId }, { $set: { paymentStatus: 'approved', plan: payment.plan } });

    res.json({ ok: true });
});

app.post('/api/admin/payments/:id/reject', auth, adminOnly, async (req, res) => {
    const payment = await Payment.findById(req.params.id);
    if (!payment) {
        return res.status(404).json({ error: 'Not found' });
    }

    // Update payment status
    payment.status = 'rejected';
    await payment.save();

    // Update the corresponding user's paymentStatus to 'rejected'
    await User.updateOne({ _id: payment.userId }, { $set: { paymentStatus: 'rejected' } });

    res.json({ ok: true });
});

app.post('/api/admin/settings', auth, adminOnly, celebrate({
    [Segments.BODY]: Joi.object({
        advancedPlanEnabled: Joi.boolean().required()
    })
}), async (req, res) => {
    const { advancedPlanEnabled } = req.body;
    await KV.updateOne({ key: 'public_settings' }, { $set: { 'data.advancedPlanEnabled': advancedPlanEnabled } }, { upsert: true });
    res.json({ ok: true });
});

app.post('/api/admin/content', auth, adminOnly, upload.single('mediaFile'), (req, res) => {
    const { subject, grade, unit, title, content } = req.body;
    const videoUrl = req.file ? `/${req.file.path.replace(/\\/g, '/')}` : null;

    const payload = { subject, grade, unit, title, content };
    if (videoUrl) {
        payload.videoUrl = videoUrl;
    }

    CourseContent.create(payload)
        .then(newContent => {
            res.status(201).json({ ok: true, content: newContent });
        })
        .catch(err => res.status(500).json({ error: 'Failed to create content', details: err.message }));
});

app.post('/api/admin/quiz', auth, adminOnly, async (req, res) => {
    // In a real app, you'd add Joi validation here
    const { subject, grade, unit, question, options, answer, explanation } = req.body;
    const newQuestion = await QuizQuestion.create({
        subject, grade, unit, question, options, answer, explanation
    });
    res.status(201).json({ ok: true, question: newQuestion });
});

app.post('/api/admin/final-exam', auth, adminOnly, async (req, res) => {
    // For final exams, we can reuse the QuizQuestion schema with a special grade/unit
    const question = await QuizQuestion.create({
        ...req.body,
        subject: 'final',
        grade: 0,
        unit: 0
    });
    res.status(201).json({ ok: true, question });
});

// Routes for common pages without .html extension
app.get('/login', (req, res) => res.sendFile('login.html', { root: '.' }));
app.get('/register', (req, res) => res.sendFile('register.html', { root: '.' }));
app.get('/admin', (req, res) => res.sendFile('admin.html', { root: '.' }));
app.get('/payment', (req, res) => res.sendFile('payment.html', { root: '.' }));
app.get('/dashboard', (req, res) => res.sendFile('dashboard.html', { root: '.' }));
app.get('/subjects', (req, res) => res.sendFile('subjects.html', { root: '.' }));
app.get('/course', (req, res) => res.sendFile('course.html', { root: '.' }));
app.get('/quiz', (req, res) => res.sendFile('quiz.html', { root: '.' }));
app.get('/schedule', (req, res) => res.sendFile('schedule.html', { root: '.' }));
app.get('/stream-selection', (req, res) => res.sendFile('stream-selection.html', { root: '.' }));
app.get('/certificate', (req, res) => res.sendFile('certificate.html', { root: '.' }));
app.get('/tips', (req, res) => res.sendFile('tips.html', { root: '.' }));

// Static frontend
app.use(express.static('.'));

// Celebrate validation error handler
app.use(celebrateErrors());

// Custom Error Handler
app.use((err, req, res, next) => { // The CSRF handler part is removed
    console.error(err); // Log the error
    const statusCode = err.statusCode || 500;
    const message = IS_PROD ? 'An unexpected error occurred' : err.message;
    res.status(statusCode).json({ error: message });
});

// Start server
export async function startServer() {
    await connectDB();
    await setupMailer();
    await seedAdmin();
    
    if (IS_PROD && JWT_SECRET === 'dev_secret') console.warn('WARNING: Using default JWT_SECRET in production!');
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

// This check prevents the server from starting automatically when running tests.
if (process.env.NODE_ENV !== 'test') {
    startServer().catch(console.error);
}
