const express = require("express");
const mysql = require("mysql2");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");

const AWS = require("aws-sdk");

const multer = require("multer");
const multerS3 = require("multer-s3");

dotenv.config();

const app = express();

app.use(express.json());
/*Place file locally*/
// const upload = multer({ dest: "uploads/" });

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});

const s3 = new AWS.S3();

const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.BUCKET,
    acl: "public-read",
    key: function (req, file, cb) {
      cb(null, Date.now().toString() + "-" + file.originalname);
    },
  }),
});

//MySQL connection configuration
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT,
});

//Connect to MySQL database
connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

/*create table*/
/*const createTableQuery = `
  CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    image varchar(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    age int NOT NULL ,
    gender VARCHAR(20) NOT NULL ,
    place VARCHAR(255) NOT NULL ,
    
  );
`;

connection.query(createTableQuery, (error) => {
  if (error) {
    console.error('Error creating table:', error);
  } else {
    console.log('Table created successfully');
  }
});*/

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/;

app.post("/register", upload.single("image"), (req, res) => {
  const { username, password, email, age, gender, place } = req.body;
  if (!req.file) {
    res.status(400).json({ error: "No file uploaded" });
    return;
  }

  if (!username || username.trim() === "") {
    res.status(400).json({ error: "username is required" });
    return;
  }
  if (!password || password.trim() === "") {
    res.status(400).json({ error: "Password is required" });
    return;
  }
  if (!passwordRegex.test(password)) {
    res.status(400).json({ error: "Invalid password format" });
    return;
  }
  if (!email || email.trim() === "") {
    res.status(400).json({ error: "email is required" });
    return;
  }
  if (!emailRegex.test(email)) {
    res.status(400).json({ error: "Invalid email format" });
    return;
  }
  if (!age) {
    res.status(400).json({ error: "age is required" });
    return;
  }
  if (!gender || gender.trim() === "") {
    res.status(400).json({ error: "gender is required" });
    return;
  }
  if (!place || place.trim() === "") {
    res.status(400).json({ error: "place is required" });
    return;
  }

  //   Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      console.error("Error hashing password:", err);
      return res.status(500).json({ error: "Internal server error" });
    }

    // Create a new user object

    const newUser = {
      image: req.file ? req.file.filename : "",
      username,
      password: hashedPassword,
      email,
      age,
      gender,
      place,
    };

    // Insert the user into the database
    connection.query("INSERT INTO users SET ?", newUser, (err, results) => {
      if (err) {
        console.error("Error registering user:", err);
        return res.status(500).json({ error: "Internal server error" });
      }

      res.status(201).json({ message: "User registered successfully" });
    });
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Find the user in the database
  connection.query(
    "SELECT * FROM users WHERE username = ?",
    username,
    (err, results) => {
      if (err) {
        console.error("Error querying user:", err);
        return res.status(500).json({ error: "Internal server error" });
      }

      if (results.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const user = results[0];

      // Compare the password
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return res.status(500).json({ error: "Internal server error" });
        }

        if (!result) {
          return res.status(401).json({ error: "Authentication failed" });
        }

        // Generate a JWT token for authentication
        const token = jwt.sign({ username: user.username }, "secretkey");
        res.json({ message: "Authentication successful", token });
      });
    }
  );
});

app.get("/users/:gender", (req, res) => {
  const gender = req.params.gender;

  // Filter users by gender in the database
  connection.query(
    "SELECT * FROM users WHERE gender = ?",
    [gender],
    (err, results) => {
      if (err) {
        console.error("Error filtering users:", err);
        return res.status(500).json({ error: "Internal server error" });
      }

      res.json(results);
    }
  );
});

// Search by username and email
app.get("/search", (req, res) => {
  const username = req.query.username;
  const email = req.query.email;
  connection.query(
    "SELECT * FROM users WHERE username = ? and email=?",
    [username, email],
    (err, results) => {
      if (err) {
        console.error("Error filtering users:", err);
        return res.status(500).json({ error: "Internal server error" });
      } else if (results.length === 0) {
        res.status(401).json({ error: "Authentication failed" });
      } else {
        res.json(results);
      }
    }
  );
});

app.put("/profile/:id", (req, res) => {
  const userId = req.params.id;
  const { name, email } = req.body;

  // Validate request body
  if (!name || !email) {
    res.status(400).json({ error: "Missing required fields" });
    return;
  }

  // Execute a MySQL query to update user data
  connection.query(
    "UPDATE users SET username = ?, email = ? WHERE id = ?",
    [name, email, userId],
    (error, results) => {
      if (error) {
        console.error("Error executing MySQL query:", error);
        res.status(500).json({ error: "Internal server error" });
      } else {
        res.json({ message: "User updated successfully" });
      }
    }
  );
});

// Start the server
app.listen(process.env.PORT || 3000, () => {
  console.log(`Server listening on port ${process.env.PORT}`);
});
