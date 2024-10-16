require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 5000;
const saltRounds = 10;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));

const CertificateSchema = new mongoose.Schema({
  filename: String,
  url: String,
  createdAt: { type: Date, default: Date.now },
});

const Certificate = mongoose.model("Certificate", CertificateSchema);

// Declare multer storage configuration for certificates
const certificateStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, "public/uploads/certificates");
    fs.mkdirSync(uploadDir, { recursive: true }); // Ensure directory exists
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});

// Define file filter to only accept image files
const certificateFileFilter = function (req, file, cb) {
  const allowedTypes = /jpeg|jpg|png|gif/;
  const isAcceptedExtension = allowedTypes.test(
    path.extname(file.originalname).toLowerCase()
  );
  const isAcceptedMimeType = allowedTypes.test(file.mimetype);

  if (isAcceptedMimeType && isAcceptedExtension) {
    cb(null, true);
  } else {
    cb(new Error("Only image files are allowed!"), false);
  }
};

// Multer upload middleware specific for certificates
const uploadCertificate = multer({
  storage: certificateStorage,
  fileFilter: certificateFileFilter,
  limits: { fileSize: 1000000 }, // Limit file size to 1MB
}).single("certificate");

// POST endpoint to handle certificate uploads and save them to MongoDB
app.post("/api/uploadCertificate", uploadCertificate, async (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }

  const newCertificate = new Certificate({
    filename: req.file.filename,
    url: `/uploads/certificates/${req.file.filename}`,
    createdAt: new Date(), // This captures the upload time
  });

  try {
    await newCertificate.save();
    res.json({ url: newCertificate.url });
  } catch (error) {
    console.error("Failed to save certificate:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

const initializeCounter = async () => {
  try {
    let counter = await Counter.findOne();
    if (!counter) {
      console.log("Counter document does not exist, creating one...");
      counter = new Counter({ count: 0 });
      await counter.save();
      console.log("Counter document created successfully.");
    }
  } catch (error) {
    console.error("Failed to initialize counter:", error);
  }
};
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB Connected");
    initializeCounter(); // Call here to ensure the counter document is initialized
  })
  .catch((err) => console.log("Database connection error:", err));

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadPath = path.join(__dirname, "public/uploads");
    fs.mkdirSync(uploadPath, { recursive: true }); // Ensure the directory exists
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 1000000 },
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Only .png, .jpg and .jpeg format allowed!"));
    }
  },
}).single("profilePic");

const StaffInfoSchema = new mongoose.Schema(
  {
    staffId: { type: Number, required: true, unique: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    profilePicUrl: { type: String },
    gender: { type: String, required: true },
  },
  { timestamps: true }
);
StaffInfoSchema.statics.findByEmail = function (email) {
  return this.findOne({ email });
};

const StaffJobSchema = new mongoose.Schema(
  {
    staffId: {
      type: mongoose.Schema.Types.ObjectId, // References an ObjectId
      ref: "StaffInfo", // Correct model name as string
      required: true,
    },
    entryYear: {
      type: Number,
      required: true,
    },
    jobTitle: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      required: true,
    },
    jobStatus: {
      type: String,
      required: true,
      enum: ["Permanent Staff", "Contract Staff"],
    },
    department: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

const PasswordSchema = new mongoose.Schema(
  {
    staffId: { type: Number, required: true, unique: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const CounterSchema = new mongoose.Schema({
  count: { type: Number, default: 0 },
});

const BoxSchema = new mongoose.Schema({
  name: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const TrainingSchema = new mongoose.Schema({
  name: String,
  location: String,
  date: String,
  duration: String,
  status: { type: String, default: "Approved" },
  editable: { type: Boolean, default: true },
  type: String, // Local, Foreign, Refresher
});

const handleSaveChanges = async (id, training, trainings, setTrainings) => {
  try {
    const response = await fetch(`/api/trainings/${id}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(training),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! Status: ${response.status}`);
    }

    const updatedTraining = await response.json();
    setTrainings(
      trainings.map((item) => (item.id === id ? updatedTraining : item))
    );
  } catch (error) {
    console.error("Failed to update the training: ", error);
  }
};

// Model creation
const StaffInfo = mongoose.model("StaffInfo", StaffInfoSchema);
const StaffJob = mongoose.model("StaffJob", StaffJobSchema);
const Password = mongoose.model("Password", PasswordSchema);
const Counter = mongoose.model("Counter", CounterSchema); // Route for handling POST requests to /api/staffinfo
const Box = mongoose.model("Box", BoxSchema);
const Training = mongoose.model("Training", TrainingSchema);

async function generateUniqueStaffId() {
  const lastRecord = await StaffInfo.findOne().sort({ staffId: -1 });
  return lastRecord ? lastRecord.staffId + 1 : 1;
}

app.post("/api/addBox", async (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ message: "Box name is required" });
  }

  try {
    const newBox = new Box({ name });
    await newBox.save();
    res.status(201).json(newBox);
  } catch (error) {
    console.error("Error adding new box:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/uploadCertificate", uploadCertificate, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send("No file uploaded.");
    }

    const newCertificate = new Certificate({
      filename: req.file.filename,
      url: `/uploads/certificates/${req.file.filename}`,
      createdAt: new Date(), // This captures the upload time
    });

    await newCertificate.save();
    res.json({ url: newCertificate.url });
  } catch (error) {
    console.error("Failed to save certificate:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/staffinfo", (req, res) => {
  upload(req, res, async (err) => {
    if (err) {
      if (err instanceof multer.MulterError) {
        console.error("Multer Error: ", err);
        return res
          .status(500)
          .json({ message: "Multer File upload error: " + err.message });
      }
      console.error("Upload Error: ", err);
      return res
        .status(500)
        .json({ message: "File upload error: " + err.message });
    }

    if (!req.file) {
      return res.status(400).json({ message: "Error: No File Selected!" });
    }

    const { firstName, lastName, email, phoneNumber, gender } = req.body;
    let { staffId } = req.body;

    staffId = parseInt(staffId, 10); // Ensure staffId is a number
    if (isNaN(staffId)) {
      return res.status(400).json({ message: "Invalid Staff ID" });
    }

    try {
      const existingUser = await StaffInfo.findOne({ staffId });
      if (existingUser) {
        return res
          .status(409)
          .json({ message: "Staff already exists with this ID" });
      }

      const newStaffInfo = new StaffInfo({
        staffId,
        firstName,
        lastName,
        email,
        phoneNumber,
        gender,
        profilePicUrl: req.file.path.replace(/\\/g, "/"),
      });

      await newStaffInfo.save();
      res.status(201).json({
        message: "Staff info saved successfully",
        data: newStaffInfo,
        staffId: staffId, // Send back the staffId to the client
      });
    } catch (error) {
      console.error("Error saving staff info:", error);
      res
        .status(500)
        .json({ message: "Internal server error: " + error.message });
    }
  });
});

app.post("/api/staffjob", async (req, res) => {
  const { entryYear, jobTitle, role, jobStatus, department } = req.body;
  let { staffId } = req.body;

  // Validate input fields
  if (
    !entryYear ||
    !jobTitle ||
    !role ||
    !jobStatus ||
    !department ||
    !staffId
  ) {
    return res.status(400).json({ message: "All fields must be filled out." });
  }

  try {
    // Convert staffId to a number and find the StaffInfo document
    staffId = parseInt(staffId, 10);
    const staffInfo = await StaffInfo.findOne({ staffId });
    if (!staffInfo) {
      return res
        .status(404)
        .json({ message: "Staff not found with provided ID." });
    }

    // Validate entryYear
    const year = Number(entryYear);
    const currentYear = new Date().getFullYear();
    if (isNaN(year) || year < 1900 || year > currentYear) {
      return res.status(400).json({
        message:
          "Invalid entry year provided. Please provide a year between 1900 and " +
          currentYear,
      });
    }

    // Create a new StaffJob document using the ObjectId of the staffInfo
    const newStaffJob = new StaffJob({
      staffId: staffInfo._id, // MongoDB ObjectId from the staffInfo document
      entryYear,
      jobTitle,
      role,
      jobStatus,
      department,
    });

    const savedStaffJob = await newStaffJob.save();
    res.status(201).json({
      message: "Job details submitted successfully",
      data: savedStaffJob,
    });
  } catch (error) {
    console.error("Error saving staff job information:", error);
    res
      .status(500)
      .json({ message: "Internal server error: " + error.message });
  }
});

app.post("/api/createpassword", async (req, res) => {
  const { staffId, createPassword, retypePassword } = req.body;

  // Check if all required fields are filled out
  if (!staffId || !createPassword || !retypePassword) {
    return res.status(400).json({ message: "All fields must be filled out" });
  }

  // Check if the passwords match
  if (createPassword !== retypePassword) {
    return res.status(400).json({ message: "Passwords do not match" });
  }

  try {
    // Convert staffId to number and check its validity
    const numericStaffId = parseInt(staffId, 10);
    if (isNaN(numericStaffId)) {
      return res.status(400).json({ message: "Invalid Staff ID" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(createPassword, saltRounds);

    // Check if a password already exists for the given staffId
    let passwordEntry = await Password.findOne({ staffId: numericStaffId });

    if (passwordEntry) {
      // Update existing password
      passwordEntry.passwordHash = hashedPassword;
      await passwordEntry.save();
    } else {
      // Create a new password entry if none exists
      passwordEntry = new Password({
        staffId: numericStaffId,
        passwordHash: hashedPassword,
      });
      await passwordEntry.save();
    }

    // Counter increment logic
    let counter = await Counter.findOne();
    if (!counter) {
      counter = new Counter({ count: 1 }); // Start at 1 on first password creation
      await counter.save();
    } else {
      counter.count += 1;
      await counter.save();
    }

    // Respond with success message
    res.status(201).json({
      message: "Password created/updated successfully",
      count: counter.count,
    });
  } catch (error) {
    console.error("Server Error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/accountCount", async (req, res) => {
  try {
    const counter = await Counter.findOne();
    if (counter) {
      res.json({ count: counter.count });
    } else {
      res.json({ count: 0 });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get count of permanent staff
app.get("/api/count/permanent", async (req, res) => {
  try {
    const count = await StaffJob.countDocuments({
      jobStatus: "Permanent Staff",
    });
    res.json({ count });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get count of contract staff
app.get("/api/count/contract", async (req, res) => {
  try {
    const count = await StaffJob.countDocuments({
      jobStatus: "Contract Staff",
    });
    res.json({ count });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.get("/api/staffinfo/:staffId", async (req, res) => {
  const { staffId } = req.params;
  try {
    const staffInfo = await StaffInfo.findOne({
      staffId: parseInt(staffId, 10),
    });
    if (!staffInfo) {
      return res.status(404).json({ message: "Staff not found" });
    }
    res.status(200).json(staffInfo);
  } catch (error) {
    console.error("Error fetching staff info:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/staffinfo/email/:email", async (req, res) => {
  const { email } = req.params;
  try {
    const staff = await StaffInfo.findOne({ email: email });
    if (!staff) {
      return res.status(404).json({ message: "Staff not found" });
    }
    res.status(200).json(staff);
  } catch (error) {
    console.error("Error fetching staff info by email:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/staffjob/:staffId", async (req, res) => {
  const numStaffId = parseInt(req.params.staffId);

  if (isNaN(numStaffId)) {
    return res.status(400).json({ message: "Invalid staff ID format." });
  }

  try {
    // First find the staff info to get the MongoDB ObjectId
    const staffInfo = await StaffInfo.findOne({ staffId: numStaffId });
    if (!staffInfo) {
      return res
        .status(404)
        .json({ message: "Staff not found with provided ID." });
    }

    // Now, use the ObjectId from staffInfo to find the job information
    const jobInfo = await StaffJob.findOne({ staffId: staffInfo._id })
      .populate("staffId") // Assuming you want to populate this data
      .exec();

    if (!jobInfo) {
      return res.status(404).json({ message: "Job information not found." });
    }

    res.status(200).json(jobInfo);
  } catch (error) {
    console.error("Error fetching job information:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/certificates", async (req, res) => {
  try {
    const certificates = await Certificate.find().sort({ createdAt: -1 }); // Get all certificates sorted by creation time
    res.status(200).json(certificates);
  } catch (error) {
    console.error("Failed to retrieve certificates:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/permanent-staff", async (req, res) => {
  try {
    const staffData = await StaffJob.find({
      jobStatus: "Permanent Staff",
    }).populate("staffId");

    const formattedData = staffData.map((doc) => {
      if (!doc.staffId) {
        console.error("Missing staff info for job:", doc);
        return { id: doc._id, error: "Missing staff info" };
      }
      return {
        id: doc.staffId.staffId,
        firstName: doc.staffId.firstName,
        lastName: doc.staffId.lastName,
        department: doc.department,
        jobTitle: doc.jobTitle,
        role: doc.role,
        yearsOfService: new Date().getFullYear() - doc.entryYear,
        email: doc.staffId.email,
        phoneNumber: doc.staffId.phoneNumber,
      };
    });

    res.json(formattedData);
  } catch (error) {
    console.error("Failed to fetch or process permanent staff data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/contract-staff", async (req, res) => {
  try {
    const staffData = await StaffJob.find({
      jobStatus: "Contract Staff",
    }).populate("staffId");

    if (!staffData.length) {
      res.status(200).json([]);
    } else {
      const formattedData = staffData.map((doc) => {
        if (!doc.staffId) {
          console.error("Missing staff info for job:", doc);
          return { id: doc._id, error: "Missing staff info" };
        }
        return {
          id: doc.staffId.staffId,
          firstName: doc.staffId.firstName,
          lastName: doc.staffId.lastName,
          department: doc.department,
          jobTitle: doc.jobTitle,
          role: doc.role,
          yearsOfService: new Date().getFullYear() - doc.entryYear,
          email: doc.staffId.email,
          phoneNumber: doc.staffId.phoneNumber,
        };
      });
      res.json(formattedData);
    }
  } catch (error) {
    console.error("Failed to fetch or process contract staff data:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/trainings", async (req, res) => {
  try {
    const trainings = await Training.find();
    res.status(200).json(trainings);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("MongoDB Connected");
    initializeCounter(); // Ensure the counter document is initialized
  })
  .catch((err) => console.log(err));

app.post("/api/login", async (req, res) => {
  const { staffId, password } = req.body;

  if (!staffId || !password) {
    return res.status(400).json({ message: "All fields must be filled out" });
  }

  try {
    const user = await Password.findOne({ staffId: staffId });

    if (user && (await bcrypt.compare(password, user.passwordHash))) {
      // Password matches
      // Assuming user is found and password matches, return staffId as part of the response
      res.json({ message: "Login successful", staffId: user.staffId });
    } else {
      // Password does not match
      res.status(401).json({ message: "Invalid staff ID or password" });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// POST - Create a new training
app.post("/api/trainings", async (req, res) => {
  const training = new Training(req.body);
  try {
    const newTraining = await training.save();
    res.status(201).json(newTraining);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// PATCH - Update existing training
app.patch("/api/trainings/:id", async (req, res) => {
  try {
    const updatedTraining = await Training.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (!updatedTraining) {
      return res.status(404).json({ message: "Training not found" });
    }
    res.json(updatedTraining);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// DELETE - Remove a training
app.delete("/api/trainings/:id", async (req, res) => {
  try {
    const result = await Training.findByIdAndDelete(req.params.id);
    if (!result) {
      return res.status(404).json({ message: "Training not found" });
    }
    res.status(200).json({ message: "Training deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

const frontendBuildPath = path.join(__dirname, "..", "frontend-gata", "build");

app.use("/public", express.static("public"));

app.use(express.static(frontendBuildPath));

app.get("*", (req, res) => {
  res.sendFile(path.join(frontendBuildPath, "index.html"));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
