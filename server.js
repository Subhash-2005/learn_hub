require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");
const app = express();

// ✅ CORS Configuration
app.use(cors({
    origin: "http://localhost:5500", // Your frontend origin
    credentials: true // Allow credentials (cookies)
}));
app.use(express.json());
app.use(cookieParser());

// ✅ Serve Static Files from "public" folder
app.use(express.static(path.join(__dirname, "public")));

// ✅ Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/learnhub", {})
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.error("❌ MongoDB Connection Error:", err));

// ✅ User Schema
const UserSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    enrolledCourses: [{ courseName: String, progress: Number }],
    securityQuestion: { type: String, required: true }, // Security question
    securityAnswer: { type: String, required: true }  // Hashed answer
});
const User = mongoose.model("User", UserSchema);

// ✅ Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: "User session expired. Please login again." });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET || "secretKey");
        req.user = verified;
        next();
    } catch (error) {
        return res.status(401).json({ message: "Session expired. Please login again." });
    }
};

// ✅ Serve HTML on Root Route
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ✅ User Registration API
app.post("/register", async (req, res) => {
    try {
        const { name, email, password, securityQuestion, securityAnswer } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        // Hash password and security answer
        const hashedPassword = await bcrypt.hash(password, 10);
        const hashedAnswer = await bcrypt.hash(securityAnswer, 10);

        // Create new user with security question and answer
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            securityQuestion,
            securityAnswer: hashedAnswer,
            enrolledCourses: []
        });

        // Save user to database
        await newUser.save();
        res.json({ message: "User registered successfully" });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ message: "Server Error. Please try again later." });
    }
});

// ✅ User Login API
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        // ✅ Generate JWT token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || "secretKey", { expiresIn: "1h" });

        // ✅ Store token in HTTP-only cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: false, // Change to true in production (HTTPS)
            sameSite: "Lax",
            maxAge: 3600000 // 1 hour expiry
        });

        res.json({ message: "Login successful", user: { name: user.name, email: user.email } });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

// ✅ Logout API
app.post("/logout", (req, res) => {
    res.clearCookie("token");
    res.json({ message: "Logged out successfully" });
});

// ✅ Update User Profile (Name Change)
app.post("/update-profile", verifyToken, async (req, res) => {
    try {
        const { name } = req.body;
        const user = await User.findById(req.user.userId);

        if (!user) return res.status(404).json({ message: "User not found" });

        user.name = name;
        await user.save();

        res.json({ message: "Profile updated successfully", name: user.name, email: user.email });
    } catch (error) {
        console.error("Profile Update Error:", error);
        res.status(500).json({ message: "Server Error. Please try again later." });
    }
});

// ✅ Forgot Password: Get Security Question
app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Send the security question for validation
        res.status(200).json({
            question: user.securityQuestion,
            message: "Answer the security question to reset your password."
        });
    } catch (error) {
        console.error("Error finding user:", error);
        res.status(500).json({ message: "Error finding user" });
    }
});

// ✅ Validate Security Answer
app.post("/validate-answer", async (req, res) => {
    const { email, securityAnswer } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Compare hashed answer
        const isMatch = await bcrypt.compare(securityAnswer, user.securityAnswer);
        if (!isMatch) {
            return res.status(400).json({ message: "Incorrect answer" });
        }

        // Send success response to allow password reset
        res.status(200).json({ message: "Answer validated. Proceed to reset your password." });
    } catch (error) {
        console.error("Error validating answer:", error);
        res.status(500).json({ message: "Error validating answer" });
    }
});

// ✅ Reset Password
app.post("/reset-password", async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the password
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({ message: "Password reset successfully" });
    } catch (error) {
        console.error("Error resetting password:", error);
        res.status(500).json({ message: "Error resetting password" });
    }
});


app.post("/update-progress", verifyToken, async (req, res) => {
    try {
        const { courseName, watchedLessons, totalLessons } = req.body;
        if (!courseName) return res.status(400).json({ message: "Course name is required." });

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        const course = user.enrolledCourses.find(course => course.courseName === courseName);
        if (course) {
            const newProgress = Math.min((watchedLessons / totalLessons) * 100, 100);
            course.progress = newProgress;
            await user.save();
            res.json({ message: "Progress updated!", progress: newProgress });
        } else {
            res.status(404).json({ message: "Course not found in enrolled courses." });
        }
    } catch (error) {
        console.error("Progress Update Error:", error);
        res.status(500).json({ message: "Server Error." });
    }
});

// ✅ Get User Profile Data
app.get("/profile", verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        res.json({ name: user.name, email: user.email, enrolledCourses: user.enrolledCourses });
    } catch (error) {
        console.error("Profile Fetch Error:", error);
        res.status(500).json({ message: "Server Error. Please try again later." });
    }
});

// ✅ Enroll in a Course
app.post("/enroll", verifyToken, async (req, res) => {
    try {
        const { courseName } = req.body;
        const user = await User.findById(req.user.userId);

        if (!user) return res.status(404).json({ message: "User not found" });

        // ✅ Check if the course already exists
        const courseExists = user.enrolledCourses.some(course => course.courseName === courseName);
        if (!courseExists) {
            user.enrolledCourses.push({ courseName, progress: 0 });
            await user.save();
        }

        res.json({ message: "Enrolled successfully", enrolledCourses: user.enrolledCourses });
    } catch (error) {
        console.error("Enrollment Error:", error);
        res.status(500).json({ message: "Server Error. Please try again later." });
    }
});

// ✅ Mark Course as Complete
// ✅ Mark Course as Complete - Sets Progress to 100%
// ✅ Mark Course as Complete - Sets Progress to 100%



// ✅ Get Course Details
app.get("/course-details", async (req, res) => {
    const courseName = req.query.name;

    const courses = {
        "Web Development": {
            title: "Web Development",
            description: "Master HTML, CSS, and JavaScript.",
            learning: ["HTML, CSS Basics", "JavaScript Fundamentals", "React.js Basics", "Responsive Design"],
            price: "$49"
        },
        "Data Science": {
            title: "Data Science",
            description: "Learn Python, Machine Learning, and AI.",
            learning: ["Python Basics", "Data Visualization", "Machine Learning Models", "Deep Learning"],
            price: "$79"
        },
        "Cybersecurity Basics": {
            title: "Cybersecurity Basics",
            description: "Learn to protect systems from vulnerabilities.",
            learning: ["Network Security", "Ethical Hacking Basics", "Malware Analysis", "Incident Response"],
            price: "$59"
        },
        "Python for Beginners": {
            title: "Python for Beginners",
            description: "Learn the basics of Python programming.",
            learning: ["Python Syntax", "Data Types", "Functions", "File Handling"],
            price: "$39"
        },
        "React.js": {
            title: "React.js",
            description: "Master React.js for front-end web development.",
            learning: ["JSX & Components", "State Management", "React Hooks", "Routing"],
            price: "$59"
        }
    };

    if (courses[courseName]) {
        res.json(courses[courseName]);
    } else {
        res.status(404).json({ message: "Course not found" });
    }
});
// ✅ Get Recommended Courses for User
// ✅ Fix: Recommended Courses Route (Ensures JSON response)
// ✅ Fix: Recommended Courses Route (Ensures JSON response)
app.get("/recommended-courses", verifyToken, async (req, res) => {
    try {
        console.log("✅ User ID from Token:", req.user.userId);  // Debugging Log

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        const allCourses = [
            { courseName: "Web Development", description: "Master HTML, CSS, and JavaScript." },
            { courseName: "Data Science", description: "Learn Python, Machine Learning, and AI." },
            { courseName: "Cybersecurity Basics", description: "Protect systems from vulnerabilities." },
            { courseName: "React.js", description: "Learn React.js for front-end development." },
            { courseName: "Python for Beginners", description: "Start coding with Python from scratch." }
        ];

        // Exclude already enrolled courses
        const recommended = allCourses.filter(course => 
            !user.enrolledCourses.some(enrolled => enrolled.courseName === course.courseName)
        );

        res.json({ recommendedCourses: recommended });
    } catch (error) {
        console.error("Error fetching recommended courses:", error);
        res.status(500).json({ message: "Server error. Try again later." });
    }
});

app.post("/mark-complete", verifyToken, async (req, res) => {
    try {
        const { courseName } = req.body;
        if (!courseName) return res.status(400).json({ message: "Course name is required" });

        const user = await User.findById(req.user.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        const course = user.enrolledCourses.find(course => course.courseName === courseName);
        if (course) {
            course.progress = 100; // ✅ Set progress to 100%
            await user.save();
            res.json({ message: "Course marked as complete!", progress: 100 });
        } else {
            res.status(404).json({ message: "Course not found in enrolled courses." });
        }
    } catch (error) {
        console.error("Progress Update Error:", error);
        res.status(500).json({ message: "Server Error. Try again later." });
    }
});

// ✅ Get All Courses API
app.get("/courses", async (req, res) => {
    try {
        const courses = [
            { name: "Web Development", description: "Master HTML, CSS, and JavaScript." },
            { name: "Data Science", description: "Learn Python, Machine Learning, and AI." },
            { name: "Cybersecurity Basics", description: "Protect systems from vulnerabilities." },
            { name: "React.js", description: "Learn React.js for front-end development." },
            { name: "Python for Beginners", description: "Start coding with Python from scratch." }
        ];

        res.json(courses);
    } catch (error) {
        console.error("Error fetching courses:", error);
        res.status(500).json({ message: "Server Error. Try again later." });
    }
});


// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
