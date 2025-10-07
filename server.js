import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import sgMail from '@sendgrid/mail';
import crypto from 'crypto';
import cron from 'node-cron';
// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// --- Middlewares ---
// CORS configuration - Manual headers for Vercel
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Lookup user by email
app.get('/api/users/by-email', async (req, res) => {
    try {
        const email = String(req.query.email || '').trim().toLowerCase();
        if (!email) return res.status(400).json({ message: 'email query param is required' });
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ healthId: user.healthId, name: user.name, role: user.role, email: user.email });
    } catch (error) {
        res.status(500).json({ message: 'Server error looking up user by email.', error: error.message });
    }
});

app.use(express.json({ limit: '25mb' })); // Increased limit for base64 file uploads
app.use(express.urlencoded({ limit: '25mb', extended: true }));

// --- SendGrid Configuration ---
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Helper function to send emails with anti-spam best practices
const sendEmail = async ({ to, subject, html }) => {
  try {
    await sgMail.send({
      from: {
        email: process.env.EMAIL_FROM,
        name: 'HealthHub Team'
      },
      to,
      subject,
      html,
      text: html.replace(/<[^>]*>/g, ''), // Plain text version
      replyTo: process.env.EMAIL_FROM,
      trackingSettings: {
        clickTracking: { enable: false },
        openTracking: { enable: false }
      },
      mailSettings: {
        bypassListManagement: { enable: false },
        sandboxMode: { enable: false }
      },
      categories: ['healthhub-notifications'],
      customArgs: {
        app: 'healthhub',
        environment: process.env.NODE_ENV || 'production'
      }
    });
    console.log(`Email sent to ${to}`);
  } catch (error) {
    console.error(`Error sending email to ${to}:`, error);
    // We don't throw an error here to not fail the main request
  }
};


// --- Mongoose Schemas ---
const AddressSchema = new mongoose.Schema({
    address1: String, address2: String, landmark: String,
    district: String, pincode: String, state: String,
}, { _id: false });

const EmergencyContactSchema = new mongoose.Schema({
    name: String, mobile: String, email: String, relation: String,
    address: AddressSchema,
}, { _id: false });

const MedicalRecordFileSchema = new mongoose.Schema({
    name: String,
    content: String, // Will store base64 data URL
}, { _id: false });

const MedicalRecordSchema = new mongoose.Schema({
    recordId: { type: String, required: true },
    name: String, category: String, disease: String,
    files: [MedicalRecordFileSchema],
    isLocked: Boolean,
    phoneForOTP: String,
    dateAdded: String, // YYYY-MM-DD
}, { _id: false });

const PermanentDiseaseSchema = new mongoose.Schema({
    name: String,
    years: String,
}, { _id: false });

const UserSchema = new mongoose.Schema({
    healthId: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    avatar: String, // Will store base64 data URL
    password: { type: String, required: true, select: false }, // Hide by default
    email: { type: String, required: true, unique: true },
    role: { type: String, enum: ['Patient', 'Admin', 'Doctor'], default: 'Patient' },
    mobileNo: String,
    birthdate: String,
    aadharNo: String,
    bloodGroup: String,
    address: AddressSchema,
    securityQuestion: String,
    securityAnswer: String,
    emergencyContact: EmergencyContactSchema,
    permanentDiseases: [PermanentDiseaseSchema],
    medicalRecords: [MedicalRecordSchema],
    appointments: [mongoose.Schema.Types.Mixed],
    prescriptions: [mongoose.Schema.Types.Mixed],
    // Doctor-specific fields
    specialization: String,
    education: String,
    experience: String,
    currentHospital: String,
    patients: [{ type: String }],
    // Patient-specific fields
    doctors: [{ type: String }],
    communications: [mongoose.Schema.Types.Mixed],
}, { timestamps: true });

// Use the 'recordId' field for the index, which matches the working sparse index in the database.
// The `sparse: true` option prevents duplicate key errors for new users who don't have medical records.
UserSchema.index({ "medicalRecords.recordId": 1 }, { unique: true, sparse: true });


// Hash password before saving
UserSchema.pre('save', async function(next) {
    // Hash password if it's been modified
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
    }
    
    next();
});

const User = mongoose.model('User', UserSchema);

const OtpSchema = new mongoose.Schema({
    email: { type: String, required: true },
    otp: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: '5m' }, // OTP expires in 5 minutes
});

const Otp = mongoose.model('Otp', OtpSchema);

const ContactMessageSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    message: { type: String, required: true },
}, { timestamps: true });

const ContactMessage = mongoose.model('ContactMessage', ContactMessageSchema);

// --- Function to create a permanent admin ---
const createPermanentAdmin = async () => {
  try {
    const adminEmail = 'krishna@gmail.com';
    const existingAdmin = await User.findOne({ email: adminEmail });

    if (!existingAdmin) {
      console.log('Permanent admin not found. Creating one...');
      const adminUser = new User({
        healthId: 'ADMIN_PERM_001', // A unique, static ID
        name: 'Krishna (Permanent Admin)',
        email: adminEmail,
        password: 'manu098', // This will be hashed by the pre-save hook
        role: 'Admin',
      });
      await adminUser.save();
      console.log('Permanent admin created successfully.');
    } else {
      console.log('Permanent admin already exists.');
    }
  } catch (error) {
    console.error('Error creating permanent admin:', error);
  }
};

// --- Database Connection ---
// The server is ready to connect to MongoDB Atlas. Add your DATABASE_URI to the .env file.
mongoose.connect(process.env.DATABASE_URI)
  .then(() => {
      console.log('MongoDB connected successfully.');
      // Create the permanent admin after connection is successful
      createPermanentAdmin();
  })
  .catch(err => console.error('MongoDB connection error:', err));


// --- AI Service Initialization ---
// Using local, rule-based generation; no external API keys required.


// --- API Routes ---

// --- Authentication Routes ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, healthId } = req.body;
        
        const existingUser = await User.findOne({ $or: [{ email }, { healthId }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email or Health ID already exists.' });
        }
        
        const newUser = new User(req.body);
        await newUser.save();
        
        const userObj = newUser.toObject();
        delete userObj.password;
        res.status(201).json(userObj);
    } catch (error) {
        if (error.code === 11000) {
             return res.status(400).json({ message: 'A database conflict occurred. This can happen if some details are too similar to an existing user.', error: error.message });
        }
        res.status(500).json({ message: 'Server error during registration.', error: error.message });
    }
});

// Delete a chat message by ID from a conversation between two users
app.delete('/api/chat/:userA/:userB/:messageId', async (req, res) => {
    try {
        const { userA, userB, messageId } = req.params;

        const [resA, resB] = await Promise.all([
            User.updateOne({ healthId: userA }, { $pull: { communications: { id: messageId } } }),
            User.updateOne({ healthId: userB }, { $pull: { communications: { id: messageId } } }),
        ]);

        if ((resA.modifiedCount || 0) === 0 && (resB.modifiedCount || 0) === 0) {
            return res.status(404).json({ message: 'Message not found in either user' });
        }
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting chat message.', error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        // Find user by either healthId or email
        const user = await User.findOne({ 
            $or: [{ healthId: identifier }, { email: identifier }] 
        }).select('+password');

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const userObj = user.toObject();
        delete userObj.password;
        res.json(userObj);
    } catch (error) {
        res.status(500).json({ message: 'Server error during login.', error: error.message });
    }
});

app.post('/api/auth/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const admin = await User.findOne({ email, role: 'Admin' }).select('+password');
        if (!admin) {
             return res.status(401).json({ message: 'Invalid admin credentials.' });
        }
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
             return res.status(401).json({ message: 'Invalid admin credentials.' });
        }
        const adminObj = admin.toObject();
        delete adminObj.password;
        res.json(adminObj);
    } catch (error) {
        res.status(500).json({ message: 'Server error during admin login.', error: error.message });
    }
});

app.post('/api/auth/request-password-reset', async (req, res) => {
    try {
        const { email, role } = req.body;
        if (!['Admin', 'Doctor'].includes(role)) {
            return res.status(400).json({ message: 'Password reset via email is only available for Doctors and Admins.' });
        }

        const user = await User.findOne({ email, role });
        if (!user) {
            return res.status(404).json({ message: `No ${role} account found with that email address.` });
        }

        const otpCode = crypto.randomInt(100000, 999999).toString();
        
        await Otp.deleteMany({ email: user.email });
        const otp = new Otp({ email: user.email, otp: otpCode });
        await otp.save();

        await sendEmail({
            to: user.email,
            subject: '🔐 HealthHub - Password Reset Code',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>
                <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                    <table width="100%" cellpadding="0" cellspacing="0" style="padding: 40px 20px;">
                        <tr>
                            <td align="center">
                                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.2);">
                                    <!-- Logo Header -->
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #27C690 0%, #1fa87a 50%, #17956b 100%); padding: 40px 30px; text-align: center;">
                                            <img src="${process.env.EMAIL_LOGO_URL || 'https://i.ibb.co/LzvTHv6/healthhub-logo.jpg'}" alt="HealthHub Logo" style="max-width: 180px; height: auto; margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;" />
                                            <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">HealthHub</h1>
                                            <p style="color: #e8f5f1; margin: 5px 0 0 0; font-size: 14px;">Your Health, Our Priority</p>
                                        </td>
                                    </tr>
                                    <!-- Content -->
                                    <tr>
                                        <td style="padding: 40px 30px;">
                                            <div style="text-align: center; margin-bottom: 30px;">
                                                <div style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 50%; padding: 20px; margin-bottom: 20px;">
                                                    <span style="font-size: 48px;">🔐</span>
                                                </div>
                                            </div>
                                            <h2 style="color: #2d3748; margin: 0 0 20px 0; font-size: 24px; text-align: center;">Password Reset Request</h2>
                                            <p style="color: #4a5568; line-height: 1.8; margin: 0 0 20px 0; font-size: 16px;">
                                                Hello <strong style="color: #27C690;">${user.name}</strong>,
                                            </p>
                                            <p style="color: #4a5568; line-height: 1.8; margin: 0 0 30px 0; font-size: 16px;">
                                                We received a request to reset your password. Use the verification code below to proceed:
                                            </p>
                                            <!-- OTP Box -->
                                            <div style="background: linear-gradient(135deg, #f0fff4 0%, #c6f6d5 100%); border: 3px dashed #27C690; border-radius: 12px; padding: 25px; margin: 30px 0; text-align: center;">
                                                <p style="margin: 0 0 10px 0; color: #2d3748; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Your Verification Code</p>
                                                <p style="margin: 0; font-size: 42px; font-weight: 900; color: #27C690; letter-spacing: 8px; font-family: 'Courier New', monospace;">${otpCode}</p>
                                            </div>
                                            <div style="background-color: #fff5f5; border-left: 4px solid #fc8181; padding: 15px; margin: 20px 0; border-radius: 4px;">
                                                <p style="margin: 0; color: #c53030; font-size: 14px; line-height: 1.6;">
                                                    ⏰ <strong>Important:</strong> This code will expire in <strong>5 minutes</strong> for your security.
                                                </p>
                                            </div>
                                            <p style="color: #718096; line-height: 1.8; margin: 20px 0; font-size: 14px; text-align: center;">
                                                If you didn't request this password reset, please ignore this email or contact our support team immediately.
                                            </p>
                                        </td>
                                    </tr>
                                    <!-- Footer -->
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); padding: 30px; text-align: center; border-top: 3px solid #27C690;">
                                            <p style="color: #718096; font-size: 13px; margin: 0 0 10px 0; line-height: 1.6;">
                                                <strong style="color: #2d3748;">HealthHub</strong> - Empowering Your Health Journey<br>
                                                📧 support@healthhub.com | 📱 +91-XXXX-XXXXXX
                                            </p>
                                            <p style="color: #a0aec0; font-size: 11px; margin: 10px 0 0 0;">
                                                © ${new Date().getFullYear()} HealthHub. All rights reserved.<br>
                                                This is an automated message, please do not reply to this email.
                                            </p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
                </html>
            `,
        });

        res.status(200).json({ message: 'OTP sent to your email address.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error sending OTP.', error: error.message });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        const otpRecord = await Otp.findOne({ email, otp });
        if (!otpRecord) {
            return res.status(400).json({ message: "Invalid or expired OTP." });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        const result = await User.updateOne({ email }, { $set: { password: hashedPassword } });
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: "User not found." });
        }
        
        await Otp.deleteOne({ _id: otpRecord._id });

        res.status(200).json({ message: 'Password has been reset successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error resetting password.', error: error.message });
    }
});


// --- User & Medical Record Routes ---
app.get('/api/users/:healthId', async (req, res) => {
    try {
        const user = await User.findOne({ healthId: req.params.healthId });
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

app.patch('/api/users/:healthId', async (req, res) => {
    try {
        const { healthId } = req.params;
        const updates = req.body;

        const currentUser = await User.findOne({ healthId });
        if (!currentUser) return res.status(404).json({ message: "User not found" });
        
        const formatTimeForEmail = (time24) => {
            if (!time24) return 'N/A';
            const [hours, minutes] = time24.split(':');
            const h = parseInt(hours, 10);
            const ampm = h >= 12 ? 'PM' : 'AM';
            const h12 = h % 12 || 12; // Convert 0 to 12
            return `${h12.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')} ${ampm}`;
        };

        // Avoid timezone shifts: format YYYY-MM-DD without constructing Date()
        const formatDateForEmail = (dateStr) => {
            if (!dateStr) return 'N/A';
            try {
                const [y, m, d] = dateStr.split('-');
                const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
                const monthIndex = Math.max(0, Math.min(11, parseInt(m, 10) - 1));
                const day = parseInt(d, 10).toString();
                return `${monthNames[monthIndex]} ${day}, ${y}`;
            } catch {
                return dateStr;
            }
        };

        // Handle appointment reminder emails for PATIENTS
        if (currentUser.role === 'Patient' && updates.appointments && currentUser.email) {
            const oldAppointments = new Map((currentUser.appointments || []).map(a => [a.id, a]));
            updates.appointments.forEach(newAppt => {
                const oldAppt = oldAppointments.get(newAppt.id);
                
                // Check if appointment was edited (date or time changed)
                if (oldAppt && (oldAppt.date !== newAppt.date || oldAppt.time !== newAppt.time)) {
                    sendEmail({
                        to: currentUser.email,
                        subject: `📅 HealthHub - Appointment Updated`,
                        html: `
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            </head>
                            <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                                <table width="100%" cellpadding="0" cellspacing="0" style="padding: 40px 20px;">
                                    <tr>
                                        <td align="center">
                                            <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.2);">
                                                <tr>
                                                    <td style="background: linear-gradient(135deg, #27C690 0%, #1fa87a 50%, #17956b 100%); padding: 40px 30px; text-align: center;">
                                                        <img src="${process.env.EMAIL_LOGO_URL || 'https://i.ibb.co/LzvTHv6/healthhub-logo.jpg'}" alt="HealthHub Logo" style="max-width: 180px; height: auto; margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;" />
                                                        <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">HealthHub</h1>
                                                        <p style="color: #e8f5f1; margin: 5px 0 0 0; font-size: 14px;">Your Health, Our Priority</p>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 40px 30px;">
                                                        <div style="text-align: center; margin-bottom: 30px;">
                                                            <div style="display: inline-block; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); border-radius: 50%; padding: 20px; margin-bottom: 20px;">
                                                                <span style="font-size: 48px;">✏️</span>
                                                            </div>
                                                        </div>
                                                        <h2 style="color: #2d3748; margin: 0 0 20px 0; font-size: 24px; text-align: center;">Appointment Updated!</h2>
                                                        <p style="color: #4a5568; line-height: 1.8; margin: 0 0 20px 0; font-size: 16px;">
                                                            Hello <strong style="color: #27C690;">${currentUser.name}</strong>,
                                                        </p>
                                                        <p style="color: #4a5568; line-height: 1.8; margin: 0 0 30px 0; font-size: 16px;">
                                                            Your appointment has been updated. Here are the new details:
                                                        </p>
                                                        <div style="background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%); border-radius: 12px; padding: 25px; margin: 30px 0;">
                                                            <table width="100%" cellpadding="8" cellspacing="0">
                                                                <tr>
                                                                    <td style="color: #92400e; font-weight: 600; font-size: 14px;">👨‍⚕️ Doctor:</td>
                                                                    <td style="color: #b45309; font-size: 16px; font-weight: 700;">Dr. ${newAppt.doctorName}</td>
                                                                </tr>
                                                                <tr>
                                                                    <td style="color: #92400e; font-weight: 600; font-size: 14px;">🏥 Hospital:</td>
                                                                    <td style="color: #b45309; font-size: 16px; font-weight: 700;">${newAppt.hospitalName}</td>
                                                                </tr>
                                                                <tr>
                                                                    <td style="color: #92400e; font-weight: 600; font-size: 14px;">📅 New Date:</td>
                                                                    <td style="color: #b45309; font-size: 16px; font-weight: 700;">${newAppt.date}</td>
                                                                </tr>
                                                                <tr>
                                                                    <td style="color: #92400e; font-weight: 600; font-size: 14px;">⏰ New Time:</td>
                                                                    <td style="color: #b45309; font-size: 16px; font-weight: 700;">${formatTimeForEmail(newAppt.time)}</td>
                                                                </tr>
                                                            </table>
                                                        </div>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); padding: 30px; text-align: center; border-top: 3px solid #27C690;">
                                                        <p style="color: #718096; font-size: 13px; margin: 0 0 10px 0; line-height: 1.6;">
                                                            <strong style="color: #2d3748;">HealthHub</strong> - Empowering Your Health Journey<br>
                                                            📧 gohealthhub.360@gmail.com
                                                        </p>
                                                        <p style="color: #a0aec0; font-size: 11px; margin: 10px 0 0 0;">
                                                            © ${new Date().getFullYear()} HealthHub. All rights reserved.<br>
                                                            This is an automated message, please do not reply to this email.
                                                        </p>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                </table>
                            </body>
                            </html>
                        `,
                    });
                }
                
                // Send email only when reminder is newly set
                if (newAppt.reminderSet && (!oldAppt || !oldAppt.reminderSet)) {
                    sendEmail({
                        to: currentUser.email,
                        subject: `📅 HealthHub - Appointment Reminder Set`,
                        html: `
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            </head>
                            <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                                <table width="100%" cellpadding="0" cellspacing="0" style="padding: 40px 20px;">
                                    <tr>
                                        <td align="center">
                                            <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.2);">
                                                <tr>
                                                    <td style="background: linear-gradient(135deg, #27C690 0%, #1fa87a 50%, #17956b 100%); padding: 40px 30px; text-align: center;">
                                                        <img src="${process.env.EMAIL_LOGO_URL || 'https://i.ibb.co/LzvTHv6/healthhub-logo.jpg'}" alt="HealthHub Logo" style="max-width: 180px; height: auto; margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;" />
                                                        <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">HealthHub</h1>
                                                        <p style="color: #e8f5f1; margin: 5px 0 0 0; font-size: 14px;">Your Health, Our Priority</p>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 40px 30px;">
                                                        <div style="text-align: center; margin-bottom: 30px;">
                                                            <div style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); border-radius: 50%; padding: 20px; margin-bottom: 20px;">
                                                                <span style="font-size: 48px;">📅</span>
                                                            </div>
                                                        </div>
                                                        <h2 style="color: #2d3748; margin: 0 0 20px 0; font-size: 24px; text-align: center;">Appointment Reminder Confirmed!</h2>
                                                        <p style="color: #4a5568; line-height: 1.8; margin: 0 0 20px 0; font-size: 16px;">
                                                            Hello <strong style="color: #27C690;">${currentUser.name}</strong>,
                                                        </p>
                                                        <p style="color: #4a5568; line-height: 1.8; margin: 0 0 30px 0; font-size: 16px;">
                                                            Your appointment reminder has been successfully set! Here are the details:
                                                        </p>
                                                        <div style="background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%); border-radius: 12px; padding: 25px; margin: 30px 0;">
                                                            <table width="100%" cellpadding="8" cellspacing="0">
                                                                <tr>
                                                                    <td style="color: #065f46; font-weight: 600; font-size: 14px;">👨‍⚕️ Doctor:</td>
                                                                    <td style="color: #047857; font-size: 16px; font-weight: 700;">Dr. ${newAppt.doctorName}</td>
                                                                </tr>
                                                                <tr>
                                                                    <td style="color: #065f46; font-weight: 600; font-size: 14px;">🏥 Hospital:</td>
                                                                    <td style="color: #047857; font-size: 16px; font-weight: 700;">${newAppt.hospitalName}</td>
                                                                </tr>
                                                                <tr>
                                                                    <td style="color: #065f46; font-weight: 600; font-size: 14px;">📅 Date:</td>
                                                                    <td style="color: #047857; font-size: 16px; font-weight: 700;">${newAppt.date}</td>
                                                                </tr>
                                                                <tr>
                                                                    <td style="color: #065f46; font-weight: 600; font-size: 14px;">⏰ Time:</td>
                                                                    <td style="color: #047857; font-size: 16px; font-weight: 700;">${formatTimeForEmail(newAppt.time)}</td>
                                                                </tr>
                                                            </table>
                                                        </div>
                                                        <div style="background-color: #eff6ff; border-left: 4px solid #3b82f6; padding: 15px; margin: 20px 0; border-radius: 4px;">
                                                            <p style="margin: 0; color: #1e40af; font-size: 14px; line-height: 1.6;">
                                                                🔔 <strong>Reminder Active:</strong> We'll send you notifications closer to your appointment time.
                                                            </p>
                                                        </div>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); padding: 30px; text-align: center; border-top: 3px solid #27C690;">
                                                        <p style="color: #718096; font-size: 13px; margin: 0 0 10px 0; line-height: 1.6;">
                                                            <strong style="color: #2d3748;">HealthHub</strong> - Empowering Your Health Journey<br>
                                                            📧 gohealthhub.360@gmail.com
                                                        </p>
                                                        <p style="color: #a0aec0; font-size: 11px; margin: 10px 0 0 0;">
                                                            © ${new Date().getFullYear()} HealthHub. All rights reserved.<br>
                                                            This is an automated message, please do not reply to this email.
                                                        </p>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                </table>
                            </body>
                            </html>
                        `,
                    });
                }
            });
        }
        
        // Handle appointment creation emails for DOCTORS setting appt for patient
        if (currentUser.role === 'Doctor' && updates.appointments) {
            const oldAppointmentIds = new Set((currentUser.appointments || []).map(a => a.id));
            const newAppointment = updates.appointments.find(appt => !oldAppointmentIds.has(appt.id));
            
            // Send to doctor as a reminder/confirmation
            if (newAppointment && currentUser.email) {
                 sendEmail({
                    to: currentUser.email,
                    subject: `📅 HealthHub - Appointment Scheduled` ,
                    html: `
                        <!DOCTYPE html>
                        <html>
                        <head>
                          <meta charset="UTF-8" />
                          <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                        </head>
                        <body style="margin:0;padding:0;font-family:Segoe UI,Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);">
                          <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
                            <tr>
                              <td align="center">
                                <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,0.2);">
                                  <tr>
                                    <td style="background:linear-gradient(135deg,#27C690 0%,#1fa87a 50%,#17956b 100%);padding:40px 30px;text-align:center;">
                                      <img src="${process.env.EMAIL_LOGO_URL || 'https://i.ibb.co/LzvTHv6/healthhub-logo.jpg'}" alt="HealthHub Logo" style="max-width:180px;height:auto;margin:0 auto 10px;display:block;" />
                                      <h1 style="color:#ffffff;margin:10px 0 0 0;font-size:28px;font-weight:700;">HealthHub</h1>
                                      <p style="color:#e8f5f1;margin:5px 0 0 0;font-size:14px;">Your Health, Our Priority</p>
                                    </td>
                                  </tr>
                                  <tr>
                                    <td style="padding:40px 30px;">
                                      <div style="text-align:center;margin-bottom:30px;">
                                        <div style="display:inline-block;background:linear-gradient(135deg,#10b981 0%,#059669 100%);border-radius:50%;padding:20px;margin-bottom:20px;">
                                          <span style="font-size:48px;">📅</span>
                                        </div>
                                      </div>
                                      <h2 style="color:#2d3748;margin:0 0 20px 0;font-size:24px;text-align:center;">Appointment Scheduled</h2>
                                      <p style="color:#4a5568;line-height:1.8;margin:0 0 20px 0;font-size:16px;text-align:center;">
                                        Hi Dr. ${currentUser.name || ''}, you have scheduled an appointment.
                                      </p>
                                      <div style="background:linear-gradient(135deg,#ecfdf5 0%,#d1fae5 100%);border-radius:12px;padding:25px;margin:30px 0;">
                                        <table width="100%" cellpadding="8" cellspacing="0">
                                          <tr>
                                            <td style="color:#065f46;font-weight:600;font-size:14px;">👤 Patient:</td>
                                            <td style="color:#047857;font-size:16px;font-weight:700;">${newAppointment.patientName || ''}</td>
                                          </tr>
                                          <tr>
                                            <td style="color:#065f46;font-weight:600;font-size:14px;">🏥 Hospital:</td>
                                            <td style="color:#047857;font-size:16px;font-weight:700;">${currentUser.currentHospital || newAppointment.hospitalName || ''}</td>
                                          </tr>
                                          <tr>
                                            <td style="color:#065f46;font-weight:600;font-size:14px;">📅 Date:</td>
                                            <td style="color:#047857;font-size:16px;font-weight:700;">${formatDateForEmail(newAppointment.date)}</td>
                                          </tr>
                                          <tr>
                                            <td style="color:#065f46;font-weight:600;font-size:14px;">⏰ Time:</td>
                                            <td style="color:#047857;font-size:16px;font-weight:700;">${formatTimeForEmail(newAppointment.time)}</td>
                                          </tr>
                                        </table>
                                      </div>
                                    </td>
                                  </tr>
                                  <tr>
                                    <td style="background:linear-gradient(135deg,#f7fafc 0%,#edf2f7 100%);padding:30px;text-align:center;border-top:3px solid #27C690;">
                                      <p style="color:#718096;font-size:13px;margin:0 0 10px 0;line-height:1.6;">
                                        <strong style="color:#2d3748;">HealthHub</strong> - Empowering Your Health Journey<br/>
                                        📧 ${process.env.EMAIL_FROM || 'support@healthhub.com'}
                                      </p>
                                      <p style="color:#a0aec0;font-size:11px;margin:10px 0 0 0;">
                                        © ${new Date().getFullYear()} HealthHub. All rights reserved.
                                      </p>
                                    </td>
                                  </tr>
                                </table>
                              </td>
                            </tr>
                          </table>
                        </body>
                        </html>
                    `,
                });
            }
        }


        // Handle medication reminder emails
        if (updates.prescriptions && currentUser.email) {
            const oldPrescriptions = new Map((currentUser.prescriptions || []).map(p => [p.id, p]));
            updates.prescriptions.forEach(newPres => {
                const oldPres = oldPrescriptions.get(newPres.id);
                
                // Check if prescription was edited
                if (oldPres) {
                    // Check if prescription details changed (doctor, hospital, date)
                    if (oldPres.doctorName !== newPres.doctorName || oldPres.hospitalName !== newPres.hospitalName || oldPres.date !== newPres.date) {
                        sendEmail({
                            to: currentUser.email,
                            subject: `💊 HealthHub - Prescription Updated`,
                            html: `
                                <!DOCTYPE html>
                                <html>
                                <head>
                                    <meta charset="UTF-8">
                                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                </head>
                                <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                                    <table width="100%" cellpadding="0" cellspacing="0" style="padding: 40px 20px;">
                                        <tr>
                                            <td align="center">
                                                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.2);">
                                                    <tr>
                                                        <td style="background: linear-gradient(135deg, #27C690 0%, #1fa87a 50%, #17956b 100%); padding: 40px 30px; text-align: center;">
                                                            <img src="${process.env.EMAIL_LOGO_URL || 'https://i.ibb.co/LzvTHv6/healthhub-logo.jpg'}" alt="HealthHub Logo" style="max-width: 180px; height: auto; margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;" />
                                                            <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">HealthHub</h1>
                                                            <p style="color: #e8f5f1; margin: 5px 0 0 0; font-size: 14px;">Your Health, Our Priority</p>
                                                        </td>
                                                    </tr>
                                                    <tr>
                                                        <td style="padding: 40px 30px;">
                                                            <div style="text-align: center; margin-bottom: 30px;">
                                                                <div style="display: inline-block; background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); border-radius: 50%; padding: 20px; margin-bottom: 20px;">
                                                                    <span style="font-size: 48px;">💊</span>
                                                                </div>
                                                            </div>
                                                            <h2 style="color: #2d3748; margin: 0 0 20px 0; font-size: 24px; text-align: center;">Prescription Updated!</h2>
                                                            <p style="color: #4a5568; line-height: 1.8; margin: 0 0 20px 0; font-size: 16px;">
                                                                Hello <strong style="color: #27C690;">${currentUser.name}</strong>,
                                                            </p>
                                                            <p style="color: #4a5568; line-height: 1.8; margin: 0 0 30px 0; font-size: 16px;">
                                                                Your prescription has been updated. Here are the new details:
                                                            </p>
                                                            <div style="background: linear-gradient(135deg, #f3e8ff 0%, #e9d5ff 100%); border-radius: 12px; padding: 25px; margin: 30px 0;">
                                                                <table width="100%" cellpadding="8" cellspacing="0">
                                                                    <tr>
                                                                        <td style="color: #6b21a8; font-weight: 600; font-size: 14px;">👨‍⚕️ Doctor:</td>
                                                                        <td style="color: #7e22ce; font-size: 16px; font-weight: 700;">Dr. ${newPres.doctorName}</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td style="color: #6b21a8; font-weight: 600; font-size: 14px;">🏥 Hospital:</td>
                                                                        <td style="color: #7e22ce; font-size: 16px; font-weight: 700;">${newPres.hospitalName}</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td style="color: #6b21a8; font-weight: 600; font-size: 14px;">📅 Date:</td>
                                                                        <td style="color: #7e22ce; font-size: 16px; font-weight: 700;">${newPres.date}</td>
                                                                    </tr>
                                                                    <tr>
                                                                        <td style="color: #6b21a8; font-weight: 600; font-size: 14px;">💊 Medications:</td>
                                                                        <td style="color: #7e22ce; font-size: 16px; font-weight: 700;">${newPres.medications.map(m => m.name).join(', ')}</td>
                                                                    </tr>
                                                                </table>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                    <tr>
                                                        <td style="background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); padding: 30px; text-align: center; border-top: 3px solid #27C690;">
                                                            <p style="color: #718096; font-size: 13px; margin: 0 0 10px 0; line-height: 1.6;">
                                                                <strong style="color: #2d3748;">HealthHub</strong> - Empowering Your Health Journey<br>
                                                                📧 gohealthhub.360@gmail.com
                                                            </p>
                                                            <p style="color: #a0aec0; font-size: 11px; margin: 10px 0 0 0;">
                                                                © ${new Date().getFullYear()} HealthHub. All rights reserved.<br>
                                                                This is an automated message, please do not reply to this email.
                                                            </p>
                                                        </td>
                                                    </tr>
                                                </table>
                                            </td>
                                        </tr>
                                    </table>
                                </body>
                                </html>
                            `,
                        });
                    }
                }
                
                if (!oldPres) return; // Only check existing prescriptions for changes

                const oldMedications = new Map(oldPres.medications.map(m => [m.id, m]));
                newPres.medications.forEach(newMed => {
                    const oldMed = oldMedications.get(newMed.id);
                    if (!oldMed) return;

                    const oldTimes = new Map(oldMed.times.map(t => [t.id, t]));
                    newMed.times.forEach(newTime => {
                        const oldTime = oldTimes.get(newTime.id);
                        // Send email only when reminder is newly set
                        if (newTime.reminderEnabled && (!oldTime || !oldTime.reminderEnabled)) {
                             sendEmail({
                                to: currentUser.email,
                                subject: `Medication Reminder Set: ${newMed.name}`,
                                html: `<p>Hi ${currentUser.name},</p><p>A reminder has been set for your medication: <strong>${newMed.name} (${newMed.dosage})</strong>, scheduled for <strong>${formatTimeForEmail(newTime.time)}</strong> daily.</p><p>You will receive notifications at the scheduled time.</p><p>Thanks,<br/>The Healthhub Team</p>`,
                            });
                        }
                    });
                });
            });
        }

        // Notify DOCTOR when an existing appointment's date/time is updated
        if (currentUser.role === 'Doctor' && Array.isArray(updates.appointments) && currentUser.email) {
            const oldAppointments = new Map((currentUser.appointments || []).map(a => [a.id, a]));
            for (const newAppt of updates.appointments) {
                const oldAppt = oldAppointments.get(newAppt.id);
                if (!oldAppt) continue; // creation handled elsewhere
                const isDateTimeChange = (oldAppt.date !== newAppt.date) || (oldAppt.time !== newAppt.time);
                if (isDateTimeChange) {
                    try {
                        await sendEmail({
                            to: currentUser.email,
                            subject: `✏️ HealthHub - Appointment Updated` ,
                            html: `
                                <!DOCTYPE html>
                                <html>
                                <head>
                                  <meta charset="UTF-8" />
                                  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                                </head>
                                <body style="margin:0;padding:0;font-family:Segoe UI,Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);">
                                  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px;">
                                    <tr><td align="center">
                                      <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,0.2);">
                                        <tr>
                                          <td style="background:linear-gradient(135deg,#27C690 0%,#1fa87a 50%,#17956b 100%);padding:40px 30px;text-align:center;">
                                            <img src="${process.env.EMAIL_LOGO_URL || 'https://i.ibb.co/LzvTHv6/healthhub-logo.jpg'}" alt="HealthHub Logo" style="max-width:180px;height:auto;margin:0 auto 10px;display:block;" />
                                            <h1 style="color:#ffffff;margin:10px 0 0 0;font-size:28px;font-weight:700;">HealthHub</h1>
                                            <p style="color:#e8f5f1;margin:5px 0 0 0;font-size:14px;">Your Health, Our Priority</p>
                                          </td>
                                        </tr>
                                        <tr>
                                          <td style="padding:40px 30px;">
                                            <div style="text-align:center;margin-bottom:30px;">
                                              <div style="display:inline-block;background:linear-gradient(135deg,#f59e0b 0%,#d97706 100%);border-radius:50%;padding:20px;margin-bottom:20px;">
                                                <span style="font-size:48px;">✏️</span>
                                              </div>
                                            </div>
                                            <h2 style="color:#2d3748;margin:0 0 20px 0;font-size:24px;text-align:center;">Appointment Updated</h2>
                                            <div style="background:linear-gradient(135deg,#fef3c7 0%,#fde68a 100%);border-radius:12px;padding:25px;margin:30px 0;">
                                              <table width="100%" cellpadding="8" cellspacing="0">
                                                <tr>
                                                  <td style="color:#92400e;font-weight:600;font-size:14px;">👤 Patient:</td>
                                                  <td style="color:#b45309;font-size:16px;font-weight:700;">${newAppt.patientName || ''}</td>
                                                </tr>
                                                <tr>
                                                  <td style="color:#92400e;font-weight:600;font-size:14px;">🏥 Hospital:</td>
                                                  <td style="color:#b45309;font-size:16px;font-weight:700;">${currentUser.currentHospital || newAppt.hospitalName || ''}</td>
                                                </tr>
                                                <tr>
                                                  <td style="color:#92400e;font-weight:600;font-size:14px;">📅 New Date:</td>
                                                  <td style="color:#b45309;font-size:16px;font-weight:700;">${formatDateForEmail(newAppt.date)}</td>
                                                </tr>
                                                <tr>
                                                  <td style="color:#92400e;font-weight:600;font-size:14px;">⏰ New Time:</td>
                                                  <td style="color:#b45309;font-size:16px;font-weight:700;">${formatTimeForEmail(newAppt.time)}</td>
                                                </tr>
                                              </table>
                                            </div>
                                          </td>
                                        </tr>
                                        <tr>
                                          <td style="background:linear-gradient(135deg,#f7fafc 0%,#edf2f7 100%);padding:30px;text-align:center;border-top:3px solid #27C690;">
                                            <p style="color:#718096;font-size:13px;margin:0 0 10px 0;line-height:1.6;">
                                              <strong style="color:#2d3748;">HealthHub</strong> - Empowering Your Health Journey<br/>
                                              📧 ${process.env.EMAIL_FROM || 'support@healthhub.com'}
                                            </p>
                                            <p style="color:#a0aec0;font-size:11px;margin:10px 0 0 0;">© ${new Date().getFullYear()} HealthHub. All rights reserved.</p>
                                          </td>
                                        </tr>
                                      </table>
                                    </td></tr>
                                  </table>
                                </body>
                                </html>
                            `,
                        });
                    } catch (e) {
                        console.error('Failed to send doctor update email:', e);
                    }
                }
            }
        }

        if (updates.password) {
            const salt = await bcrypt.genSalt(10);
            updates.password = await bcrypt.hash(updates.password, salt);
        }

        const updatedUser = await User.findOneAndUpdate({ healthId }, { $set: updates }, { new: true });
        
        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ message: 'Server error during update.', error: error.message });
    }
});


app.post('/api/users/:healthId/medical-records', async (req, res) => {
    try {
        const { healthId } = req.params;
        const recordData = req.body;
        
        // The file content is already a base64 data URL from the frontend.
        // We will store it directly instead of uploading to an external service.

        // Generate a unique ID for the new record
        recordData.recordId = `REC_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;

        // **FIX**: Using `updateOne` with `$push` is a more direct database operation.
        // This avoids Mongoose's full-document validation which was causing errors
        // by trying to re-validate old, malformed records in the user's `medicalRecords` array.
        // This is a more robust way to add a single item to a sub-array.
        const updateResult = await User.updateOne(
            { healthId },
            { $push: { medicalRecords: recordData } }
        );

        if (updateResult.matchedCount === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        
        if (updateResult.modifiedCount === 0) {
            return res.status(500).json({ message: "Failed to update user record." });
        }

        res.status(201).json(recordData);
    } catch (error) {
        console.error('Error adding medical record:', error);
        res.status(500).json({ message: "Server error adding record.", error: error.message });
    }
});


app.get('/api/users/:healthId/medical-records', async (req, res) => {
    try {
        const user = await User.findOne({ healthId: req.params.healthId });
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user.medicalRecords || []);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching records.', error: error.message });
    }
});

app.delete('/api/users/:healthId/medical-records/:recordId', async (req, res) => {
    try {
        const { healthId, recordId } = req.params;

        const result = await User.updateOne(
            { healthId },
            { $pull: { medicalRecords: { recordId: recordId } } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        if (result.modifiedCount === 0) {
            return res.status(404).json({ message: "Medical record not found" });
        }

        res.status(204).send(); // Success, no content
    } catch (error) {
        console.error('Error deleting medical record:', error);
        res.status(500).json({ message: "Server error deleting record.", error: error.message });
    }
});


// --- OTP Routes for record locking ---
app.post('/api/records/request-otp', async (req, res) => {
    try {
        const { healthId } = req.body;
        const user = await User.findOne({ healthId });
        if (!user || !user.email) {
            return res.status(404).json({ message: "User or user email not found." });
        }

        // Generate 6-digit OTP
        const otpCode = crypto.randomInt(100000, 999999).toString();
        
        // Save OTP to DB
        await Otp.deleteMany({ email: user.email }); // Remove old OTPs
        const otp = new Otp({ email: user.email, otp: otpCode });
        await otp.save();

        // Send OTP via Email
        await sendEmail({
            to: user.email,
            subject: '🏥 HealthHub - Medical Record Access Code',
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>
                <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                    <table width="100%" cellpadding="0" cellspacing="0" style="padding: 40px 20px;">
                        <tr>
                            <td align="center">
                                <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.2);">
                                    <!-- Logo Header -->
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #27C690 0%, #1fa87a 50%, #17956b 100%); padding: 40px 30px; text-align: center;">
                                            <img src="${process.env.EMAIL_LOGO_URL || 'https://i.ibb.co/LzvTHv6/healthhub-logo.jpg'}" alt="HealthHub Logo" style="max-width: 180px; height: auto; margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;" />
                                            <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">HealthHub</h1>
                                            <p style="color: #e8f5f1; margin: 5px 0 0 0; font-size: 14px;">Your Health, Our Priority</p>
                                        </td>
                                    </tr>
                                    <!-- Content -->
                                    <tr>
                                        <td style="padding: 40px 30px;">
                                            <div style="text-align: center; margin-bottom: 30px;">
                                                <div style="display: inline-block; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); border-radius: 50%; padding: 20px; margin-bottom: 20px;">
                                                    <span style="font-size: 48px;">🏥</span>
                                                </div>
                                            </div>
                                            <h2 style="color: #2d3748; margin: 0 0 20px 0; font-size: 24px; text-align: center;">Secure Medical Record Access</h2>
                                            <p style="color: #4a5568; line-height: 1.8; margin: 0 0 20px 0; font-size: 16px;">
                                                Hello <strong style="color: #27C690;">${user.name}</strong>,
                                            </p>
                                            <p style="color: #4a5568; line-height: 1.8; margin: 0 0 30px 0; font-size: 16px;">
                                                A request was made to access your secure medical records. Use the verification code below:
                                            </p>
                                            <!-- OTP Box -->
                                            <div style="background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); border: 3px dashed #3b82f6; border-radius: 12px; padding: 25px; margin: 30px 0; text-align: center;">
                                                <p style="margin: 0 0 10px 0; color: #2d3748; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">Your Verification Code</p>
                                                <p style="margin: 0; font-size: 42px; font-weight: 900; color: #3b82f6; letter-spacing: 8px; font-family: 'Courier New', monospace;">${otpCode}</p>
                                            </div>
                                            <div style="background-color: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; margin: 20px 0; border-radius: 4px;">
                                                <p style="margin: 0; color: #dc2626; font-size: 14px; line-height: 1.6;">
                                                    ⏰ <strong>Important:</strong> This code will expire in <strong>5 minutes</strong> for your security.
                                                </p>
                                            </div>
                                            <div style="background-color: #fffbeb; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; border-radius: 4px;">
                                                <p style="margin: 0; color: #d97706; font-size: 14px; line-height: 1.6;">
                                                    🔒 <strong>Security Alert:</strong> If you didn't request this access, please secure your account immediately and contact support.
                                                </p>
                                            </div>
                                        </td>
                                    </tr>
                                    <!-- Footer -->
                                    <tr>
                                        <td style="background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%); padding: 30px; text-align: center; border-top: 3px solid #27C690;">
                                            <p style="color: #718096; font-size: 13px; margin: 0 0 10px 0; line-height: 1.6;">
                                                <strong style="color: #2d3748;">HealthHub</strong> - Empowering Your Health Journey<br>
                                                📧 support@healthhub.com | 📱 +91-XXXX-XXXXXX
                                            </p>
                                            <p style="color: #a0aec0; font-size: 11px; margin: 10px 0 0 0;">
                                                © ${new Date().getFullYear()} HealthHub. All rights reserved.<br>
                                                This is an automated message, please do not reply to this email.
                                            </p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
                </html>
            `,
        });

        res.status(200).json({ message: 'OTP sent successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error sending OTP.', error: error.message });
    }
});

app.post('/api/records/verify-otp', async (req, res) => {
    try {
        const { healthId, otp } = req.body;
        const user = await User.findOne({ healthId });
        if (!user || !user.email) {
            return res.status(404).json({ message: "User not found." });
        }

        const otpRecord = await Otp.findOne({ email: user.email, otp });
        if (!otpRecord) {
            return res.status(400).json({ message: "Invalid or expired OTP." });
        }

        // OTP is valid, remove it
        await Otp.deleteOne({ _id: otpRecord._id });

        res.status(200).json({ message: 'OTP verified successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error verifying OTP.', error: error.message });
    }
});


// --- AI Service Routes (Local rule-based) ---
app.post('/api/ai/generate-diet-plan', async (req, res) => {
    try {
        const { healthCondition } = req.body;
        if (!healthCondition) {
            return res.status(400).json({ message: "Health condition is required." });
        }

        const lc = String(healthCondition || '').toLowerCase();
        const plans = {
            diabetes: {
                morning: { mealName: 'Oats with Nuts', description: 'Low GI oats topped with almonds and chia; no added sugar.' },
                afternoon: { mealName: 'Grilled Chicken + Salad', description: 'Lean protein with mixed greens and olive oil-lemon dressing.' },
                evening: { mealName: 'Greek Yogurt', description: 'Unsweetened yogurt with a few berries for fiber.' },
                night: { mealName: 'Dal + Quinoa', description: 'Lentil dal with quinoa and sautéed non-starchy veggies.' },
            },
            hypertension: {
                morning: { mealName: 'Veg Poha (Low Salt)', description: 'Flattened rice with peas, carrots, and lemon; go easy on salt.' },
                afternoon: { mealName: 'Brown Rice + Rajma', description: 'Fiber-rich rice with kidney beans and cucumber salad.' },
                evening: { mealName: 'Fruit + Nuts', description: 'One seasonal fruit with a handful of unsalted nuts.' },
                night: { mealName: 'Grilled Fish/Tofu + Veg', description: 'Omega-3 rich fish or tofu with steamed vegetables.' },
            },
            obesity: {
                morning: { mealName: 'Moong Chilla', description: 'Protein-rich lentil pancakes with mint chutney.' },
                afternoon: { mealName: 'Millet Bowl', description: 'Foxtail/bajra millet with sautéed veggies and sprouts.' },
                evening: { mealName: 'Buttermilk', description: 'Light spiced buttermilk to curb hunger.' },
                night: { mealName: 'Paneer Bhurji + Salad', description: 'Cottage cheese scramble with lots of salad; minimal oil.' },
            },
            heart: {
                morning: { mealName: 'Oat Porridge + Flaxseed', description: 'Heart-healthy oats with ground flaxseed and berries.' },
                afternoon: { mealName: 'Salmon + Quinoa', description: 'Omega-3 rich fish with quinoa and steamed broccoli.' },
                evening: { mealName: 'Walnuts + Apple', description: 'Handful of walnuts with a fresh apple.' },
                night: { mealName: 'Vegetable Soup', description: 'Low-sodium vegetable soup with whole grain bread.' },
            },
            kidney: {
                morning: { mealName: 'White Bread + Egg White', description: 'Low-phosphorus breakfast with egg whites and cucumber.' },
                afternoon: { mealName: 'Rice + Cabbage Sabzi', description: 'White rice with low-potassium cabbage curry.' },
                evening: { mealName: 'Apple Slices', description: 'Fresh apple slices; kidney-friendly fruit.' },
                night: { mealName: 'Pasta + Bell Peppers', description: 'Plain pasta with sautéed bell peppers; low sodium.' },
            },
            thyroid: {
                morning: { mealName: 'Scrambled Eggs + Spinach', description: 'Protein-rich eggs with iron-rich spinach.' },
                afternoon: { mealName: 'Chicken + Sweet Potato', description: 'Lean protein with complex carbs; avoid soy.' },
                evening: { mealName: 'Brazil Nuts', description: 'Selenium-rich nuts for thyroid support; limit to 2-3.' },
                night: { mealName: 'Fish + Asparagus', description: 'Iodine-rich fish with fiber-rich asparagus.' },
            },
            pcod: {
                morning: { mealName: 'Egg + Avocado Toast', description: 'Protein and healthy fats on whole grain bread.' },
                afternoon: { mealName: 'Grilled Chicken + Salad', description: 'Lean protein with leafy greens and olive oil.' },
                evening: { mealName: 'Almonds + Berries', description: 'Low-GI snack with antioxidants.' },
                night: { mealName: 'Salmon + Broccoli', description: 'Anti-inflammatory omega-3s with cruciferous veggies.' },
            },
            asthma: {
                morning: { mealName: 'Oatmeal + Banana', description: 'Anti-inflammatory oats with potassium-rich banana.' },
                afternoon: { mealName: 'Grilled Fish + Spinach', description: 'Omega-3 rich fish with magnesium-rich greens.' },
                evening: { mealName: 'Carrot Sticks + Hummus', description: 'Beta-carotene rich snack for lung health.' },
                night: { mealName: 'Chicken Soup + Veggies', description: 'Warm, anti-inflammatory soup with root vegetables.' },
            },
            arthritis: {
                morning: { mealName: 'Turmeric Milk + Almonds', description: 'Anti-inflammatory turmeric with healthy fats.' },
                afternoon: { mealName: 'Salmon + Sweet Potato', description: 'Omega-3s and vitamin A to reduce inflammation.' },
                evening: { mealName: 'Walnuts + Cherries', description: 'Anti-inflammatory nuts and antioxidant-rich cherries.' },
                night: { mealName: 'Lentil Soup + Ginger', description: 'Protein-rich lentils with anti-inflammatory ginger.' },
            },
            anemia: {
                morning: { mealName: 'Spinach Paratha + Curd', description: 'Iron-rich spinach with vitamin B12 from curd.' },
                afternoon: { mealName: 'Chicken Liver + Rice', description: 'High iron content with vitamin C-rich tomatoes.' },
                evening: { mealName: 'Dates + Nuts', description: 'Iron and energy-boosting natural snack.' },
                night: { mealName: 'Beetroot Curry + Roti', description: 'Iron-rich beetroot with whole wheat for absorption.' },
            },
            gastric: {
                morning: { mealName: 'Banana + Oats', description: 'Gentle on stomach; high in soluble fiber.' },
                afternoon: { mealName: 'Boiled Rice + Curd', description: 'Easy to digest; probiotics for gut health.' },
                evening: { mealName: 'Coconut Water', description: 'Alkaline drink to soothe acidity.' },
                night: { mealName: 'Vegetable Khichdi', description: 'Light, easily digestible one-pot meal.' },
            },
            liver: {
                morning: { mealName: 'Green Tea + Oats', description: 'Antioxidants for liver detox with fiber.' },
                afternoon: { mealName: 'Grilled Chicken + Broccoli', description: 'Lean protein with liver-supporting cruciferous veggies.' },
                evening: { mealName: 'Grapefruit', description: 'Vitamin C and antioxidants for liver cleansing.' },
                night: { mealName: 'Beetroot Salad + Quinoa', description: 'Liver-detoxifying beets with complete protein.' },
            },
            gout: {
                morning: { mealName: 'Low-Fat Milk + Cereal', description: 'Low-purine breakfast with calcium.' },
                afternoon: { mealName: 'Vegetable Stir-Fry + Rice', description: 'Plant-based, low-purine meal with complex carbs.' },
                evening: { mealName: 'Cherries + Water', description: 'Anti-inflammatory cherries; stay hydrated.' },
                night: { mealName: 'Tofu + Mixed Veggies', description: 'Low-purine protein with alkaline vegetables.' },
            },
            migraine: {
                morning: { mealName: 'Oatmeal + Almonds', description: 'Magnesium-rich foods to prevent headaches.' },
                afternoon: { mealName: 'Salmon + Quinoa', description: 'Omega-3s and B vitamins for nerve health.' },
                evening: { mealName: 'Banana + Water', description: 'Potassium and hydration to prevent triggers.' },
                night: { mealName: 'Spinach Soup + Bread', description: 'Magnesium-rich greens; avoid tyramine foods.' },
            },
            ibs: {
                morning: { mealName: 'Scrambled Eggs + Toast', description: 'Low-FODMAP protein with white bread.' },
                afternoon: { mealName: 'Grilled Chicken + Rice', description: 'Easily digestible lean protein with white rice.' },
                evening: { mealName: 'Lactose-Free Yogurt', description: 'Probiotics without lactose trigger.' },
                night: { mealName: 'Steamed Fish + Carrots', description: 'Gentle on gut; low-FODMAP vegetables.' },
            },
            osteoporosis: {
                morning: { mealName: 'Milk + Fortified Cereal', description: 'Calcium and vitamin D for bone strength.' },
                afternoon: { mealName: 'Paneer + Spinach', description: 'Calcium-rich cottage cheese with vitamin K.' },
                evening: { mealName: 'Almonds + Dried Figs', description: 'Calcium and magnesium for bone density.' },
                night: { mealName: 'Salmon + Broccoli', description: 'Vitamin D and calcium for bone health.' },
            },
            cancer: {
                morning: { mealName: 'Berry Smoothie + Flaxseed', description: 'Antioxidant-rich berries with omega-3s.' },
                afternoon: { mealName: 'Grilled Fish + Cruciferous Veggies', description: 'Anti-cancer compounds in broccoli and cauliflower.' },
                evening: { mealName: 'Green Tea + Walnuts', description: 'Polyphenols and healthy fats for cell protection.' },
                night: { mealName: 'Turmeric Lentil Soup', description: 'Curcumin and plant protein for immune support.' },
            },
            cholesterol: {
                morning: { mealName: 'Oat Bran + Berries', description: 'Soluble fiber to lower LDL cholesterol.' },
                afternoon: { mealName: 'Grilled Salmon + Avocado', description: 'Omega-3s and healthy fats to raise HDL.' },
                evening: { mealName: 'Almonds + Apple', description: 'Fiber and healthy fats for heart health.' },
                night: { mealName: 'Lentil Soup + Barley', description: 'Plant sterols and soluble fiber.' },
            },
            pregnancy: {
                morning: { mealName: 'Fortified Cereal + Milk', description: 'Folic acid and calcium for fetal development.' },
                afternoon: { mealName: 'Grilled Chicken + Spinach', description: 'Iron and protein for maternal health.' },
                evening: { mealName: 'Greek Yogurt + Berries', description: 'Calcium and antioxidants for pregnancy.' },
                night: { mealName: 'Salmon + Sweet Potato', description: 'DHA for brain development; vitamin A.' },
            },
            lactation: {
                morning: { mealName: 'Oats + Fenugreek Seeds', description: 'Galactagogues to boost milk production.' },
                afternoon: { mealName: 'Chicken Soup + Veggies', description: 'Protein and hydration for nursing mothers.' },
                evening: { mealName: 'Almonds + Dates', description: 'Healthy fats and energy for lactation.' },
                night: { mealName: 'Paneer + Spinach', description: 'Calcium and iron for mother and baby.' },
            },
            menopause: {
                morning: { mealName: 'Soy Milk + Flaxseed', description: 'Phytoestrogens to balance hormones.' },
                afternoon: { mealName: 'Grilled Fish + Broccoli', description: 'Calcium and vitamin D for bone health.' },
                evening: { mealName: 'Edamame + Sesame', description: 'Plant estrogens and calcium.' },
                night: { mealName: 'Tofu Stir-Fry + Quinoa', description: 'Isoflavones and complete protein.' },
            },
            constipation: {
                morning: { mealName: 'Prune Juice + Whole Wheat Toast', description: 'Natural laxative with fiber.' },
                afternoon: { mealName: 'Brown Rice + Rajma', description: 'High fiber beans and whole grains.' },
                evening: { mealName: 'Papaya + Flaxseeds', description: 'Digestive enzymes and fiber.' },
                night: { mealName: 'Vegetable Soup + Bran', description: 'Fiber-rich meal for bowel movement.' },
            },
            diarrhea: {
                morning: { mealName: 'Banana + White Rice', description: 'BRAT diet; binding foods for loose stools.' },
                afternoon: { mealName: 'Boiled Potato + Curd', description: 'Probiotics and easy-to-digest carbs.' },
                evening: { mealName: 'Coconut Water', description: 'Electrolyte replacement; hydration.' },
                night: { mealName: 'Plain Khichdi', description: 'Gentle on stomach; easy to digest.' },
            },
            uti: {
                morning: { mealName: 'Cranberry Juice + Oats', description: 'Prevent bacteria adhesion; hydration.' },
                afternoon: { mealName: 'Grilled Chicken + Cucumber', description: 'Lean protein with hydrating vegetables.' },
                evening: { mealName: 'Watermelon + Water', description: 'High water content to flush bacteria.' },
                night: { mealName: 'Vegetable Soup + Garlic', description: 'Antimicrobial properties; hydration.' },
            },
            skin: {
                morning: { mealName: 'Berry Smoothie + Chia', description: 'Antioxidants and omega-3s for skin health.' },
                afternoon: { mealName: 'Salmon + Sweet Potato', description: 'Vitamin A and omega-3s for glow.' },
                evening: { mealName: 'Walnuts + Pomegranate', description: 'Healthy fats and antioxidants.' },
                night: { mealName: 'Spinach Salad + Avocado', description: 'Vitamin E and healthy fats for skin.' },
            },
            hair: {
                morning: { mealName: 'Eggs + Spinach', description: 'Biotin and iron for hair growth.' },
                afternoon: { mealName: 'Grilled Chicken + Lentils', description: 'Protein and zinc for strong hair.' },
                evening: { mealName: 'Almonds + Berries', description: 'Vitamin E and antioxidants.' },
                night: { mealName: 'Salmon + Quinoa', description: 'Omega-3s and protein for hair health.' },
            },
            stress: {
                morning: { mealName: 'Oatmeal + Banana', description: 'Complex carbs and tryptophan for mood.' },
                afternoon: { mealName: 'Grilled Fish + Leafy Greens', description: 'Omega-3s and magnesium to reduce stress.' },
                evening: { mealName: 'Dark Chocolate + Almonds', description: 'Mood-boosting antioxidants.' },
                night: { mealName: 'Chamomile Tea + Whole Grain', description: 'Calming herbs and B vitamins.' },
            },
            insomnia: {
                morning: { mealName: 'Whole Grain Cereal + Milk', description: 'Tryptophan for sleep regulation.' },
                afternoon: { mealName: 'Turkey + Brown Rice', description: 'Tryptophan and complex carbs.' },
                evening: { mealName: 'Banana + Almonds', description: 'Magnesium and melatonin precursors.' },
                night: { mealName: 'Warm Milk + Honey', description: 'Sleep-inducing amino acids.' },
            },
            depression: {
                morning: { mealName: 'Eggs + Whole Wheat Toast', description: 'Vitamin D and complex carbs for mood.' },
                afternoon: { mealName: 'Salmon + Quinoa', description: 'Omega-3s and B vitamins for brain health.' },
                evening: { mealName: 'Walnuts + Dark Chocolate', description: 'Mood-boosting healthy fats.' },
                night: { mealName: 'Chicken + Sweet Potato', description: 'Tryptophan and vitamin B6.' },
            },
            anxiety: {
                morning: { mealName: 'Greek Yogurt + Berries', description: 'Probiotics for gut-brain axis.' },
                afternoon: { mealName: 'Grilled Fish + Spinach', description: 'Omega-3s and magnesium to calm nerves.' },
                evening: { mealName: 'Chamomile Tea + Almonds', description: 'Calming herbs and magnesium.' },
                night: { mealName: 'Turkey + Asparagus', description: 'Tryptophan and folate for mood.' },
            },
            fever: {
                morning: { mealName: 'Citrus Juice + Toast', description: 'Vitamin C and easy-to-digest carbs.' },
                afternoon: { mealName: 'Chicken Soup + Rice', description: 'Hydration and easy protein.' },
                evening: { mealName: 'Coconut Water', description: 'Electrolyte replacement; hydration.' },
                night: { mealName: 'Vegetable Broth + Crackers', description: 'Light, hydrating, easy to digest.' },
            },
            cold: {
                morning: { mealName: 'Ginger Tea + Honey Toast', description: 'Anti-inflammatory and soothing.' },
                afternoon: { mealName: 'Chicken Soup + Garlic', description: 'Immune-boosting; clears congestion.' },
                evening: { mealName: 'Orange + Warm Water', description: 'Vitamin C for immunity.' },
                night: { mealName: 'Turmeric Milk + Honey', description: 'Anti-inflammatory and soothing.' },
            },
            immunity: {
                morning: { mealName: 'Citrus Smoothie + Ginger', description: 'Vitamin C and antioxidants.' },
                afternoon: { mealName: 'Grilled Chicken + Broccoli', description: 'Protein and vitamin C for immunity.' },
                evening: { mealName: 'Almonds + Berries', description: 'Vitamin E and antioxidants.' },
                night: { mealName: 'Turmeric Lentil Soup', description: 'Curcumin and plant protein.' },
            },
            energy: {
                morning: { mealName: 'Banana + Peanut Butter', description: 'Quick energy from natural sugars and protein.' },
                afternoon: { mealName: 'Quinoa Bowl + Chicken', description: 'Complete protein and complex carbs.' },
                evening: { mealName: 'Dates + Nuts', description: 'Natural energy boost.' },
                night: { mealName: 'Sweet Potato + Lentils', description: 'Sustained energy from complex carbs.' },
            },
            muscle: {
                morning: { mealName: 'Egg White Omelette + Oats', description: 'High protein for muscle building.' },
                afternoon: { mealName: 'Grilled Chicken + Brown Rice', description: 'Lean protein and complex carbs.' },
                evening: { mealName: 'Greek Yogurt + Berries', description: 'Protein for muscle recovery.' },
                night: { mealName: 'Salmon + Quinoa', description: 'Complete protein and omega-3s.' },
            },
            backpain: {
                morning: { mealName: 'Anti-Inflammatory Smoothie', description: 'Berries, spinach, and ginger to reduce inflammation.' },
                afternoon: { mealName: 'Salmon + Leafy Greens', description: 'Omega-3s and magnesium for muscle relaxation.' },
                evening: { mealName: 'Walnuts + Cherries', description: 'Anti-inflammatory compounds.' },
                night: { mealName: 'Turmeric Milk + Almonds', description: 'Curcumin for pain relief.' },
            },
            copd: {
                morning: { mealName: 'Oatmeal + Berries', description: 'Antioxidants for lung health.' },
                afternoon: { mealName: 'Grilled Fish + Broccoli', description: 'Omega-3s and vitamin C.' },
                evening: { mealName: 'Carrot Juice', description: 'Beta-carotene for respiratory health.' },
                night: { mealName: 'Chicken Soup + Ginger', description: 'Easy to digest; anti-inflammatory.' },
            },
            adhd: {
                morning: { mealName: 'Eggs + Whole Grain Toast', description: 'Protein and complex carbs for focus.' },
                afternoon: { mealName: 'Salmon + Quinoa', description: 'Omega-3s for brain function.' },
                evening: { mealName: 'Walnuts + Apple', description: 'Healthy fats and fiber.' },
                night: { mealName: 'Turkey + Sweet Potato', description: 'Tryptophan and B vitamins.' },
            },
            vertigo: {
                morning: { mealName: 'Ginger Tea + Toast', description: 'Ginger helps reduce dizziness.' },
                afternoon: { mealName: 'Grilled Chicken + Rice', description: 'Easy to digest; stable energy.' },
                evening: { mealName: 'Banana + Water', description: 'Potassium and hydration.' },
                night: { mealName: 'Vegetable Soup', description: 'Light meal; avoid triggers.' },
            },
            hemorrhoids: {
                morning: { mealName: 'Prune Juice + Oats', description: 'High fiber to ease bowel movements.' },
                afternoon: { mealName: 'Brown Rice + Beans', description: 'Fiber-rich to prevent straining.' },
                evening: { mealName: 'Papaya + Flaxseeds', description: 'Natural laxative and fiber.' },
                night: { mealName: 'Vegetable Soup + Bran', description: 'Soft, fiber-rich meal.' },
            },
            gingivitis: {
                morning: { mealName: 'Green Tea + Whole Grain', description: 'Antioxidants for gum health.' },
                afternoon: { mealName: 'Grilled Fish + Spinach', description: 'Omega-3s and vitamin C.' },
                evening: { mealName: 'Carrot Sticks + Hummus', description: 'Crunchy foods clean teeth naturally.' },
                night: { mealName: 'Yogurt + Berries', description: 'Probiotics for oral health.' },
            },
            acne: {
                morning: { mealName: 'Green Smoothie + Chia', description: 'Antioxidants and omega-3s for clear skin.' },
                afternoon: { mealName: 'Grilled Chicken + Salad', description: 'Lean protein; avoid dairy and sugar.' },
                evening: { mealName: 'Walnuts + Berries', description: 'Anti-inflammatory healthy fats.' },
                night: { mealName: 'Salmon + Asparagus', description: 'Zinc and omega-3s for skin repair.' },
            },
            eczema: {
                morning: { mealName: 'Oatmeal + Flaxseed', description: 'Anti-inflammatory omega-3s.' },
                afternoon: { mealName: 'Salmon + Sweet Potato', description: 'Omega-3s and vitamin A for skin.' },
                evening: { mealName: 'Almonds + Berries', description: 'Vitamin E and antioxidants.' },
                night: { mealName: 'Turmeric Lentil Soup', description: 'Anti-inflammatory curcumin.' },
            },
            psoriasis: {
                morning: { mealName: 'Berry Smoothie + Flaxseed', description: 'Antioxidants and omega-3s.' },
                afternoon: { mealName: 'Grilled Fish + Leafy Greens', description: 'Anti-inflammatory diet.' },
                evening: { mealName: 'Walnuts + Pomegranate', description: 'Healthy fats and antioxidants.' },
                night: { mealName: 'Turmeric Chicken + Veggies', description: 'Curcumin for inflammation.' },
            },
            conjunctivitis: {
                morning: { mealName: 'Carrot Juice + Toast', description: 'Vitamin A for eye health.' },
                afternoon: { mealName: 'Grilled Fish + Spinach', description: 'Omega-3s and antioxidants.' },
                evening: { mealName: 'Almonds + Berries', description: 'Vitamin E for healing.' },
                night: { mealName: 'Chicken Soup + Veggies', description: 'Immune support.' },
            },
            cataracts: {
                morning: { mealName: 'Spinach Smoothie', description: 'Lutein and zeaxanthin for eye health.' },
                afternoon: { mealName: 'Salmon + Kale', description: 'Omega-3s and antioxidants.' },
                evening: { mealName: 'Carrot Sticks + Almonds', description: 'Vitamin A and E.' },
                night: { mealName: 'Egg + Broccoli', description: 'Lutein-rich foods.' },
            },
            glaucoma: {
                morning: { mealName: 'Leafy Green Smoothie', description: 'Nitrates to improve blood flow to eyes.' },
                afternoon: { mealName: 'Salmon + Spinach', description: 'Omega-3s for eye pressure.' },
                evening: { mealName: 'Berries + Walnuts', description: 'Antioxidants for optic nerve.' },
                night: { mealName: 'Egg + Kale', description: 'Lutein and zeaxanthin.' },
            },
            sinusitis: {
                morning: { mealName: 'Ginger Tea + Honey Toast', description: 'Anti-inflammatory; clears sinuses.' },
                afternoon: { mealName: 'Chicken Soup + Garlic', description: 'Steam and antimicrobial properties.' },
                evening: { mealName: 'Pineapple + Water', description: 'Bromelain reduces inflammation.' },
                night: { mealName: 'Turmeric Milk', description: 'Anti-inflammatory for sinus relief.' },
            },
            fibromyalgia: {
                morning: { mealName: 'Oatmeal + Berries', description: 'Anti-inflammatory and energy-sustaining.' },
                afternoon: { mealName: 'Grilled Fish + Quinoa', description: 'Omega-3s and magnesium for pain.' },
                evening: { mealName: 'Almonds + Dark Chocolate', description: 'Magnesium for muscle relaxation.' },
                night: { mealName: 'Turkey + Sweet Potato', description: 'Tryptophan for better sleep.' },
            },
            tinnitus: {
                morning: { mealName: 'Oatmeal + Banana', description: 'Magnesium and potassium for ear health.' },
                afternoon: { mealName: 'Salmon + Spinach', description: 'Omega-3s and zinc.' },
                evening: { mealName: 'Pineapple + Almonds', description: 'Anti-inflammatory compounds.' },
                night: { mealName: 'Chicken + Asparagus', description: 'B vitamins for nerve health.' },
            },
            nausea: {
                morning: { mealName: 'Ginger Tea + Crackers', description: 'Ginger soothes nausea naturally.' },
                afternoon: { mealName: 'Plain Rice + Boiled Potato', description: 'Bland, easy to digest.' },
                evening: { mealName: 'Banana + Water', description: 'Gentle on stomach.' },
                night: { mealName: 'Clear Broth + Toast', description: 'Light and soothing.' },
            },
            indigestion: {
                morning: { mealName: 'Papaya + Ginger Tea', description: 'Digestive enzymes and soothing.' },
                afternoon: { mealName: 'Grilled Chicken + Steamed Veggies', description: 'Easy to digest protein.' },
                evening: { mealName: 'Fennel Tea + Crackers', description: 'Relieves bloating.' },
                night: { mealName: 'Plain Khichdi', description: 'Gentle on digestive system.' },
            },
            menstrual: {
                morning: { mealName: 'Oatmeal + Banana', description: 'Magnesium and B6 for cramps.' },
                afternoon: { mealName: 'Salmon + Spinach', description: 'Omega-3s and iron.' },
                evening: { mealName: 'Dark Chocolate + Almonds', description: 'Magnesium for muscle relaxation.' },
                night: { mealName: 'Ginger Tea + Whole Grain', description: 'Anti-inflammatory for pain relief.' },
            },
            sweating: {
                morning: { mealName: 'Green Tea + Whole Grain', description: 'Antioxidants; avoid caffeine excess.' },
                afternoon: { mealName: 'Grilled Chicken + Cucumber', description: 'Lean protein and hydrating foods.' },
                evening: { mealName: 'Watermelon + Mint', description: 'Cooling and hydrating.' },
                night: { mealName: 'Vegetable Salad', description: 'Light meal; avoid spicy foods.' },
            },
            general: {
                morning: { mealName: 'Idli + Sambar', description: 'Steamed idlis with lentil-vegetable sambar.' },
                afternoon: { mealName: 'Roti + Dal + Sabzi', description: 'Whole-wheat rotis with dal and seasonal vegetable.' },
                evening: { mealName: 'Roasted Chana', description: 'High-protein snack; keep portion moderate.' },
                night: { mealName: 'Khichdi + Curd', description: 'Light moong dal khichdi with plain curd.' },
            },
        };

        // Enhanced keyword matching for more diseases
        const selected = 
            (lc.includes('diab') || lc.includes('sugar'))
                ? plans.diabetes
            : (lc.includes('hyper') || lc.includes('bp') || lc.includes('blood pressure') || lc.includes('high blood'))
                ? plans.hypertension
            : (lc.includes('obes') || lc.includes('weight') || lc.includes('overweight'))
                ? plans.obesity
            : (lc.includes('heart') || lc.includes('cardiac'))
                ? plans.heart
            : (lc.includes('cholesterol') || lc.includes('ldl') || lc.includes('hdl'))
                ? plans.cholesterol
            : (lc.includes('kidney') || lc.includes('renal'))
                ? plans.kidney
            : (lc.includes('thyroid') || lc.includes('hypothyroid') || lc.includes('hyperthyroid'))
                ? plans.thyroid
            : (lc.includes('pcod') || lc.includes('pcos') || lc.includes('polycystic'))
                ? plans.pcod
            : (lc.includes('asthma') || lc.includes('breathing') || lc.includes('respiratory'))
                ? plans.asthma
            : (lc.includes('arthritis') || lc.includes('joint') || lc.includes('rheumatoid'))
                ? plans.arthritis
            : (lc.includes('anemia') || lc.includes('anaemia') || lc.includes('iron deficiency'))
                ? plans.anemia
            : (lc.includes('gastric') || lc.includes('acidity') || lc.includes('gerd') || lc.includes('acid reflux'))
                ? plans.gastric
            : (lc.includes('liver') || lc.includes('hepatic') || lc.includes('fatty liver'))
                ? plans.liver
            : (lc.includes('gout') || lc.includes('uric acid'))
                ? plans.gout
            : (lc.includes('migraine') || lc.includes('headache'))
                ? plans.migraine
            : (lc.includes('ibs') || lc.includes('irritable bowel'))
                ? plans.ibs
            : (lc.includes('osteoporosis') || lc.includes('calcium deficiency'))
                ? plans.osteoporosis
            : (lc.includes('cancer') || lc.includes('tumor') || lc.includes('oncology'))
                ? plans.cancer
            : (lc.includes('pregnan') || lc.includes('expecting') || lc.includes('maternal'))
                ? plans.pregnancy
            : (lc.includes('lactat') || lc.includes('breastfeed') || lc.includes('nursing'))
                ? plans.lactation
            : (lc.includes('menopause') || lc.includes('hot flash') || lc.includes('perimenopause'))
                ? plans.menopause
            : (lc.includes('constipat') || lc.includes('bowel movement'))
                ? plans.constipation
            : (lc.includes('diarr') || lc.includes('loose stool') || lc.includes('loose motion'))
                ? plans.diarrhea
            : (lc.includes('uti') || lc.includes('urinary tract') || lc.includes('bladder infection'))
                ? plans.uti
            : (lc.includes('skin') || lc.includes('acne') || lc.includes('eczema') || lc.includes('psoriasis'))
                ? plans.skin
            : (lc.includes('hair') || lc.includes('hair loss') || lc.includes('baldness'))
                ? plans.hair
            : (lc.includes('stress') || lc.includes('tension'))
                ? plans.stress
            : (lc.includes('insomnia') || lc.includes('sleep') || lc.includes('sleepless'))
                ? plans.insomnia
            : (lc.includes('depress') || lc.includes('sad') || lc.includes('mood'))
                ? plans.depression
            : (lc.includes('anxiety') || lc.includes('panic') || lc.includes('nervous'))
                ? plans.anxiety
            : (lc.includes('fever') || lc.includes('temperature') || lc.includes('pyrexia'))
                ? plans.fever
            : (lc.includes('cold') || lc.includes('flu') || lc.includes('cough') || lc.includes('congestion'))
                ? plans.cold
            : (lc.includes('immun') || lc.includes('weak immunity') || lc.includes('boost immunity'))
                ? plans.immunity
            : (lc.includes('energy') || lc.includes('fatigue') || lc.includes('tired') || lc.includes('weakness'))
                ? plans.energy
            : (lc.includes('muscle') || lc.includes('bodybuilding') || lc.includes('gym') || lc.includes('workout'))
                ? plans.muscle
            : (lc.includes('back pain') || lc.includes('backache') || lc.includes('lower back') || lc.includes('spine'))
                ? plans.backpain
            : (lc.includes('copd') || lc.includes('chronic obstructive') || lc.includes('emphysema') || lc.includes('bronchitis'))
                ? plans.copd
            : (lc.includes('adhd') || lc.includes('attention deficit') || lc.includes('hyperactivity'))
                ? plans.adhd
            : (lc.includes('vertigo') || lc.includes('dizzy') || lc.includes('dizziness') || lc.includes('balance'))
                ? plans.vertigo
            : (lc.includes('hemorrhoid') || lc.includes('piles') || lc.includes('rectal'))
                ? plans.hemorrhoids
            : (lc.includes('gingivitis') || lc.includes('gum') || lc.includes('periodontal'))
                ? plans.gingivitis
            : (lc.includes('acne') || lc.includes('pimple') || lc.includes('breakout'))
                ? plans.acne
            : (lc.includes('eczema') || lc.includes('dermatitis') || lc.includes('atopic'))
                ? plans.eczema
            : (lc.includes('psoriasis') || lc.includes('plaque') || lc.includes('scaly skin'))
                ? plans.psoriasis
            : (lc.includes('conjunctivitis') || lc.includes('pink eye') || lc.includes('eye infection'))
                ? plans.conjunctivitis
            : (lc.includes('cataract') || lc.includes('cloudy vision') || lc.includes('lens'))
                ? plans.cataracts
            : (lc.includes('glaucoma') || lc.includes('eye pressure') || lc.includes('optic nerve'))
                ? plans.glaucoma
            : (lc.includes('sinusitis') || lc.includes('sinus') || lc.includes('nasal'))
                ? plans.sinusitis
            : (lc.includes('fibromyalgia') || lc.includes('chronic pain') || lc.includes('muscle pain'))
                ? plans.fibromyalgia
            : (lc.includes('tinnitus') || lc.includes('ringing') || lc.includes('ear noise'))
                ? plans.tinnitus
            : (lc.includes('nausea') || lc.includes('vomit') || lc.includes('sick') || lc.includes('queasiness'))
                ? plans.nausea
            : (lc.includes('indigestion') || lc.includes('dyspepsia') || lc.includes('bloat'))
                ? plans.indigestion
            : (lc.includes('menstrual') || lc.includes('period') || lc.includes('cramp') || lc.includes('pms'))
                ? plans.menstrual
            : (lc.includes('sweat') || lc.includes('hyperhidrosis') || lc.includes('perspir'))
                ? plans.sweating
            : plans.general;

        return res.json(selected);
    } catch (error) {
        console.error('Diet Plan Error:', error);
        res.status(500).json({ message: 'Failed to generate diet plan.', error: error.message });
    }
});

app.get('/api/ai/generate-health-tip', async (_req, res) => {
    try {
        const tips = [
            'Drink water first thing in the morning.',
            'Take a 10-minute walk to break up long sitting periods.',
            'Eat one colorful fruit or vegetable with every meal.',
            'Stretch or move your body gently when you wake up.',
            'Wash your hands for 20 seconds before eating.',
            'Unplug from screens at least an hour before bedtime.',
            'Practice deep breathing during stressful moments.',
            'Floss your teeth once every day.',
            'Stand up straight and check your posture frequently.',
            'Get sunlight exposure early in the day.',
            'Eat a high-protein breakfast to sustain energy.',
            'Choose the stairs over the elevator.',
            'Listen to soothing music to de-stress.',
            'Take a break every 60 minutes when working.',
            'Limit added sugar in drinks and snacks.',
            'Tidy up one small area for mental clarity.',
            'Do one kind thing for someone else today.',
            'Avoid smoking and second-hand smoke.',
            'Laugh genuinely at least once a day.',
            'Check your medication schedule daily.',
            'Maintain a consistent sleep and wake time.',
            'Clean/wipe down frequently touched surfaces.',
            'Practice active listening in conversations.',
            'Plan your next meal to ensure it\'s healthy.',
            'Wear sunglasses outdoors to protect your eyes.',
            'Fill half your plate with vegetables at lunch and dinner.',
            'Sleep 7–9 hours; keep a consistent bedtime.',
            'Keep healthy snacks visible; hide ultra-processed foods.',
            'Add strength training twice a week for muscle health.',
            'Drink at least 8 glasses of water throughout the day.',
            'Take the stairs instead of the elevator when possible.',
            'Eat slowly and chew your food thoroughly.',
            'Schedule regular health check-ups and screenings.',
            'Practice gratitude by noting three good things daily.',
            'Reduce screen time before bed for better sleep.',
            'Include probiotics in your diet for gut health.',
            'Do light stretching exercises before bedtime.',
            'Avoid processed foods and choose whole foods.',
            'Take short breaks to rest your eyes when using screens.',
            'Stay socially connected with friends and family.'
        ];
        const tip = tips[Math.floor(Math.random() * tips.length)];
        return res.json({ tip });
    } catch (error) {
        console.error('Health Tip Error:', error);
        res.status(500).json({ message: 'Failed to generate health tip.', error: error.message });
    }
});


// --- Contact Form Route ---
app.post('/api/contact', async (req, res) => {
    try {
        const { name, email, message } = req.body;
        if (!name || !email || !message) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        const newMessage = new ContactMessage({ name, email, message });
        await newMessage.save();
        res.status(201).json({ message: 'Message received successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error saving message.', error: error.message });
    }
});


// --- Admin Routes ---
app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await User.find({});
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

app.post('/api/admin/users', async (req, res) => {
    // This is essentially the same as register, but for admin use
    try {
        const { email, healthId } = req.body;
        const existingUser = await User.findOne({ $or: [{ email }, { healthId }] });
        if (existingUser) {
            return res.status(400).json({ message: 'User with this email or Health ID already exists.' });
        }
        const newUser = new User(req.body);
        await newUser.save();
        const userObj = newUser.toObject();
        delete userObj.password;
        res.status(201).json(userObj);
    } catch (error) {
        res.status(500).json({ message: 'Server error adding user.', error: error.message });
    }
});

app.delete('/api/admin/users/:healthId', async (req, res) => {
    try {
        const { healthId } = req.params;
        const userToDelete = await User.findOne({ healthId });

        if (!userToDelete) {
             return res.status(404).json({ message: 'User not found' });
        }
        // Prevent permanent admin deletion
        if (userToDelete.email === 'krishna@gmail.com') {
             return res.status(403).json({ message: 'Permanent admin cannot be deleted.' });
        }

        await User.deleteOne({ healthId });
        res.status(204).send(); // No content
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting user.', error: error.message });
    }
});

app.get('/api/admin/messages', async (req, res) => {
    try {
        const messages = await ContactMessage.find({}).sort({ createdAt: -1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching messages.', error: error.message });
    }
});

app.delete('/api/admin/messages/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await ContactMessage.findByIdAndDelete(id);
        if (!result) {
            return res.status(404).json({ message: 'Message not found.' });
        }
        res.status(204).send(); // No content, successful deletion
    } catch (error) {
        res.status(500).json({ message: 'Server error deleting message.', error: error.message });
    }
});


// --- Doctor-Patient Linking Routes ---
app.get('/api/doctors/:doctorId/patients', async (req, res) => {
    try {
        const doctor = await User.findOne({ healthId: req.params.doctorId, role: 'Doctor' });
        if (!doctor || !doctor.patients || doctor.patients.length === 0) {
            return res.json([]);
        }
        const patients = await User.find({ healthId: { $in: doctor.patients } });
        res.json(patients);
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

app.post('/api/doctors/:doctorId/patients', async (req, res) => {
    try {
        const { doctorId } = req.params;
        const { patientHealthId } = req.body;
        
        // Add patient to doctor's list
        await User.updateOne({ healthId: doctorId }, { $addToSet: { patients: patientHealthId } });
        // Add doctor to patient's list
        await User.updateOne({ healthId: patientHealthId }, { $addToSet: { doctors: doctorId } });

        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

app.delete('/api/doctors/:doctorId/patients/:patientHealthId', async (req, res) => {
    try {
        const { doctorId, patientHealthId } = req.params;
        // Remove patient from doctor's list
        await User.updateOne({ healthId: doctorId }, { $pull: { patients: patientHealthId } });
        // Remove doctor from patient's list
        await User.updateOne({ healthId: patientHealthId }, { $pull: { doctors: doctorId } });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

// --- Patient-Doctor Linking Routes ---
app.get('/api/patients/:patientId/doctors', async (req, res) => {
    try {
        const patient = await User.findOne({ healthId: req.params.patientId });
        if (!patient || !patient.doctors || patient.doctors.length === 0) {
            return res.json([]);
        }
        const doctors = await User.find({ healthId: { $in: patient.doctors } });
        res.json(doctors);
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

app.post('/api/patients/:patientId/doctors', async (req, res) => {
    try {
        const { patientId } = req.params;
        const { doctorIdentifier } = req.body; // Can be healthId or email

        const doctor = await User.findOne({
            role: 'Doctor',
            $or: [{ healthId: doctorIdentifier }, { email: doctorIdentifier }]
        });
        if (!doctor) return res.status(404).json({ message: 'Doctor with that ID or email not found.' });
        
        await User.updateOne({ healthId: patientId }, { $addToSet: { doctors: doctor.healthId } });
        await User.updateOne({ healthId: doctor.healthId }, { $addToSet: { patients: patientId } });

        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

app.delete('/api/patients/:patientId/doctors/:doctorId', async (req, res) => {
     try {
        const { patientId, doctorId } = req.params;
        await User.updateOne({ healthId: patientId }, { $pull: { doctors: doctorId } });
        await User.updateOne({ healthId: doctorId }, { $pull: { patients: patientId } });
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Server error.', error: error.message });
    }
});

// --- Communications ---
app.post('/api/communications/to-patient', async (req, res) => {
    try {
        const { patientId, fromDoctor, message, imageUrl } = req.body;

        const newComm = {
            id: `COMM_${Date.now()}`,
            from: fromDoctor,
            toId: patientId,
            timestamp: new Date().toISOString(),
            message,
            imageUrl: imageUrl ? imageUrl : undefined,
            read: false,
        };

        const updateResult = await User.updateOne(
            { healthId: patientId },
            { $push: { communications: { $each: [newComm], $position: 0 } } }
        );

        if (updateResult.matchedCount === 0) {
            return res.status(404).json({ message: "Patient not found" });
        }

        res.status(201).json(newComm);
    } catch(error) {
        res.status(500).json({ message: 'Server error sending communication.', error: error.message });
    }
});

app.post('/api/communications/from-patient', async (req, res) => {
     try {
        const { doctorId, fromPatient, message } = req.body;
        const doctor = await User.findOne({ healthId: doctorId });
        if (!doctor) return res.status(404).json({ message: "Doctor not found" });

        const newComm = {
            id: `COMM_${Date.now()}`,
            from: fromPatient,
            toId: doctorId,
            timestamp: new Date().toISOString(),
            message,
            read: false,
        };

        const updateResult = await User.updateOne(
            { healthId: doctorId },
            { $push: { communications: { $each: [newComm], $position: 0 } } }
        );
        if (updateResult.matchedCount === 0) {
            return res.status(404).json({ message: 'Doctor not found' });
        }
        res.status(201).json(newComm);
    } catch(error) {
        res.status(500).json({ message: 'Server error sending communication.', error: error.message });
    }
});

// Unified Chat APIs
// Fetch a conversation between two users (doctor <-> patient) by merging both sides' communications
app.get('/api/chat/:userA/:userB', async (req, res) => {
    try {
        const { userA, userB } = req.params; // healthIds
        const [a, b] = await Promise.all([
            User.findOne({ healthId: userA }),
            User.findOne({ healthId: userB }),
        ]);
        if (!a || !b) return res.status(404).json({ message: 'One or both users not found' });

        // Messages sent TO A by B are stored on A if B is a doctor (to-patient route)
        const msgsToAFromB = (a.communications || []).filter(m => m.from?.id === userB && m.toId === userA);
        // Messages sent TO B by A are stored on B when A is a patient (from-patient route)
        const msgsToBFromA = (b.communications || []).filter(m => m.from?.id === userA && m.toId === userB);

        const messages = [...msgsToAFromB, ...msgsToBFromA]
            .filter(m => !!m?.timestamp)
            .sort((x, y) => new Date(x.timestamp).getTime() - new Date(y.timestamp).getTime());

        res.json({
            participants: [
                { id: a.healthId, name: a.name, role: a.role },
                { id: b.healthId, name: b.name, role: b.role },
            ],
            messages,
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error fetching chat.', error: error.message });
    }
});

// Mark messages from peer as read for a given user
app.post('/api/chat/mark-read', async (req, res) => {
    try {
        const { userId, peerId } = req.body;
        if (!userId || !peerId) return res.status(400).json({ message: 'userId and peerId are required' });

        const result = await User.updateOne(
            { healthId: userId },
            { $set: { 'communications.$[elem].read': true } },
            { arrayFilters: [ { 'elem.from.id': peerId, 'elem.toId': userId, 'elem.read': { $ne: true } } ] }
        );

        res.json({ modifiedCount: result.modifiedCount || 0 });
    } catch (error) {
        res.status(500).json({ message: 'Server error marking messages as read.', error: error.message });
    }
});

// Send a chat message from any role; store it on the recipient's document communications array
app.post('/api/chat/send', async (req, res) => {
    try {
        const { fromId, toId, message, imageUrl, replyTo, recordShare } = req.body;
        if (!fromId || !toId || (!message && !imageUrl)) {
            return res.status(400).json({ message: 'fromId, toId and message or imageUrl are required.' });
        }

        const [fromUser, toUser] = await Promise.all([
            User.findOne({ healthId: fromId }),
            User.findOne({ healthId: toId }),
        ]);
        if (!fromUser || !toUser) return res.status(404).json({ message: 'Sender or recipient not found' });

        const newComm = {
            id: `COMM_${Date.now()}`,
            from: { id: fromUser.healthId, name: fromUser.name },
            toId: toUser.healthId,
            timestamp: new Date().toISOString(),
            message,
            imageUrl: imageUrl ? imageUrl : undefined,
            read: false,
            replyTo: replyTo && replyTo.id ? {
                id: String(replyTo.id),
                message: replyTo.message || undefined,
                imageUrl: replyTo.imageUrl || undefined,
                from: replyTo.from ? { id: String(replyTo.from.id), name: String(replyTo.from.name || '') } : undefined,
                timestamp: replyTo.timestamp || undefined,
            } : undefined,
            recordShare: recordShare && recordShare.recordId ? {
                recordId: String(recordShare.recordId),
                name: String(recordShare.name || ''),
                category: recordShare.category || undefined,
                disease: recordShare.disease || undefined,
                files: Array.isArray(recordShare.files) ? recordShare.files.map(f => ({
                    name: String(f.name || 'file'),
                    content: String(f.content || ''),
                })) : undefined,
                dateAdded: recordShare.dateAdded || undefined,
            } : undefined,
        };

        const updateResult = await User.updateOne(
            { healthId: toUser.healthId },
            { $push: { communications: { $each: [newComm], $position: 0 } } }
        );
        if (updateResult.matchedCount === 0) {
            return res.status(404).json({ message: 'Recipient not found' });
        }

        res.status(201).json(newComm);
    } catch (error) {
        res.status(500).json({ message: 'Server error sending chat message.', error: error.message });
    }
});

// --- Email Reminder System ---
// Store sent reminders in memory (resets on server restart)
const sentReminders = new Set();

const checkAndSendReminders = async () => {
    try {
        const now = new Date();
        const users = await User.find({});

        for (const user of users) {
            // Check Appointments
            if (user.appointments && user.appointments.length > 0) {
                for (const appointment of user.appointments) {
                    const appointmentDateTime = new Date(`${appointment.date}T${appointment.time}`);
                    const timeDiff = appointmentDateTime - now;
                    const hoursDiff = timeDiff / (1000 * 60 * 60);

                    // Send reminder 6 hours before
                    const reminder6HKey = `${user.healthId}_${appointment.id}_6h`;
                    if (hoursDiff > 5.9 && hoursDiff <= 6.1 && !sentReminders.has(reminder6HKey)) {
                        await sendAppointmentReminder(user, appointment, '6 hours');
                        sentReminders.add(reminder6HKey);
                    }

                    // Send reminder at appointment time (within 5 minutes)
                    const reminderNowKey = `${user.healthId}_${appointment.id}_now`;
                    if (Math.abs(timeDiff) <= 5 * 60 * 1000 && !sentReminders.has(reminderNowKey)) {
                        await sendAppointmentReminder(user, appointment, 'now');
                        sentReminders.add(reminderNowKey);
                    }
                }
            }

            // Check Medications
            if (user.medications && user.medications.length > 0) {
                for (const medication of user.medications) {
                    if (medication.times && medication.times.length > 0) {
                        for (let i = 0; i < medication.times.length; i++) {
                            const medTime = medication.times[i];
                            const [hours, minutes] = medTime.split(':');
                            const medDateTime = new Date(now);
                            medDateTime.setHours(parseInt(hours), parseInt(minutes), 0, 0);
                            
                            const timeDiff = medDateTime - now;
                            const minutesDiff = timeDiff / (1000 * 60);

                            // Send reminder 5 minutes before
                            const reminder5MinKey = `${user.healthId}_${medication.medicationId}_${medTime}_5min_${now.toDateString()}`;
                            if (minutesDiff > 4.5 && minutesDiff <= 5.5 && !sentReminders.has(reminder5MinKey)) {
                                await sendMedicationReminder(user, medication, medTime, '5 minutes');
                                sentReminders.add(reminder5MinKey);
                            }

                            // Send reminder at medication time
                            const reminderNowKey = `${user.healthId}_${medication.medicationId}_${medTime}_now_${now.toDateString()}`;
                            if (Math.abs(timeDiff) <= 60 * 1000 && !sentReminders.has(reminderNowKey)) {
                                await sendMedicationReminder(user, medication, medTime, 'now');
                                sentReminders.add(reminderNowKey);
                            }
                        }
                    }
                }
            }
        }
    } catch (error) {
        console.error('Error in reminder system:', error);
    }
};

const sendAppointmentReminder = async (user, appointment, timing) => {
    const subject = timing === 'now' 
        ? '🏥 Your Appointment is Now!' 
        : '⏰ Appointment Reminder - 6 Hours to Go';
    
    const message = timing === 'now'
        ? `Your appointment is scheduled for now!`
        : `Your appointment is in 6 hours.`;

    // Parse appointment date to get month and day
    const apptDate = new Date(appointment.date);
    const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const month = monthNames[apptDate.getMonth()];
    const day = apptDate.getDate();

    const html = `
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <table width="100%" cellpadding="0" cellspacing="0" style="padding: 40px 20px;">
                    <tr>
                        <td align="center">
                            <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.2);">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #27C690 0%, #1fa87a 50%, #17956b 100%); padding: 40px 30px; text-align: center;">
                                        <div style="width: 80px; height: 80px; margin: 0 auto 15px; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                                            <span style="font-size: 48px;">🏥</span>
                                        </div>
                                        <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700;">HealthHub</h1>
                                        <p style="color: #e8f5f1; margin: 5px 0 0 0; font-size: 14px;">Appointment Reminder</p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 40px 30px; text-align: center;">
                                        <div style="display: inline-block; background: linear-gradient(135deg, #10b981 0%, #059669 100%); border-radius: 50%; padding: 20px; margin-bottom: 20px;">
                                            <div style="background: white; border-radius: 12px; padding: 15px 20px; min-width: 80px;">
                                                <div style="background: #ef4444; color: white; font-size: 12px; font-weight: bold; padding: 4px 8px; border-radius: 4px 4px 0 0; margin: -15px -20px 8px -20px;">${month}</div>
                                                <div style="font-size: 36px; font-weight: bold; color: #1f2937; line-height: 1;">${day}</div>
                                            </div>
                                        </div>
                                        <h2 style="color: #333; margin-bottom: 10px; font-size: 24px;">Hello ${user.name},</h2>
                                        <p style="color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">${message}</p>
                                        <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: left;">
                                            <p style="margin: 8px 0;"><strong style="color: #047857;">Hospital:</strong> <span style="color: #666;">${appointment.hospitalName || 'N/A'}</span></p>
                                            <p style="margin: 8px 0;"><strong style="color: #047857;">Doctor:</strong> <span style="color: #666;">${appointment.doctorName || appointment.patientName || 'N/A'}</span></p>
                                            <p style="margin: 8px 0;"><strong style="color: #047857;">Date:</strong> <span style="color: #666;">${appointment.date}</span></p>
                                            <p style="margin: 8px 0;"><strong style="color: #047857;">Time:</strong> <span style="color: #666;">${appointment.time}</span></p>
                                        </div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
        </html>
    `;

    await sendEmail({ to: user.email, subject, html });
};

const sendMedicationReminder = async (user, medication, time, timing) => {
    const subject = timing === 'now' 
        ? '💊 Time to Take Your Medication!' 
        : '⏰ Medication Reminder - 5 Minutes';
    
    const message = timing === 'now'
        ? `It's time to take your medication!`
        : `Reminder: Take your medication in 5 minutes.`;

    const html = `
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <table width="100%" cellpadding="0" cellspacing="0" style="padding: 40px 20px;">
                    <tr>
                        <td align="center">
                            <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.2);">
                                <tr>
                                    <td style="background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); padding: 40px 30px; text-align: center;">
                                        <div style="width: 80px; height: 80px; margin: 0 auto 15px; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                                            <span style="font-size: 48px;">💊</span>
                                        </div>
                                        <h1 style="color: #ffffff; margin: 10px 0 0 0; font-size: 28px; font-weight: 700;">HealthHub</h1>
                                        <p style="color: #f3e8ff; margin: 5px 0 0 0; font-size: 14px;">Medication Reminder</p>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 40px 30px; text-align: center;">
                                        <div style="display: inline-block; background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); border-radius: 50%; padding: 20px; margin-bottom: 20px;">
                                            <span style="font-size: 48px;">⏰</span>
                                        </div>
                                        <h2 style="color: #333; margin-bottom: 10px; font-size: 24px;">Hello ${user.name},</h2>
                                        <p style="color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 25px;">${message}</p>
                                        <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: left;">
                                            <p style="margin: 8px 0;"><strong style="color: #7c3aed;">Medication:</strong> <span style="color: #666;">${medication.name}</span></p>
                                            <p style="margin: 8px 0;"><strong style="color: #7c3aed;">Dosage:</strong> <span style="color: #666;">${medication.dosage}</span></p>
                                            <p style="margin: 8px 0;"><strong style="color: #7c3aed;">Time:</strong> <span style="color: #666;">${time}</span></p>
                                            ${medication.instructions ? `<p style="margin: 8px 0;"><strong style="color: #7c3aed;">Instructions:</strong> <span style="color: #666;">${medication.instructions}</span></p>` : ''}
                                        </div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
        </html>
    `;

    await sendEmail({ to: user.email, subject, html });
};

// Run reminder check every minute
cron.schedule('* * * * *', () => {
    console.log('Checking for reminders...');
    checkAndSendReminders();
});

// Keep-alive: Ping the server every 10 minutes to prevent Render free tier from sleeping
cron.schedule('*/10 * * * *', async () => {
    try {
        const serverUrl = process.env.SERVER_URL || 'https://healthhub-backend-wlhxonrender.com';
        const response = await fetch(`${serverUrl}/api/health`);
        console.log(`Keep-alive ping: ${response.status} - ${new Date().toISOString()}`);
    } catch (error) {
        console.error('Keep-alive ping failed:', error.message);
    }
});

// Health check endpoint for keep-alive
app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// --- Server Listener ---
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log('Email reminder system is active');
  console.log('Keep-alive system is active');
});

// Export for Vercel serverless (if needed)
export default app;