LearnHub

LearnHub is an interactive online learning platform designed to provide high-quality courses, progress tracking.

🚀 Features

User Authentication (Signup, Login, Forgot Password)

Course Management (Add, View, and Track Progress)

Modern UI Design (Glassmorphism, Neumorphism)

Discussion Forums for Collaboration

🛠 Tech Stack

Frontend: HTML, CSS, JavaScript, React

Backend: Node.js, Express.js

Database: MongoDB (with Mongoose)

Authentication: JWT (JSON Web Tokens)

Styling: Tailwind CSS

📂 Project Structure

LearnHub/
│── backend/ (Server-side code)
│── frontend/ (React-based UI)
│── public/ (Static assets)
│── .env (Environment variables)
│── package.json (Project dependencies)
│── server.js (Backend server setup)

🚀 Installation & Setup

1️⃣ Clone the Repository

git clone https://github.com/your-username/LearnHub.git
cd LearnHub

2️⃣ Install Dependencies

npm install

3️⃣ Setup Environment Variables

Create a .env file and add:

MONGO_URI=your-mongodb-connection-string
PORT=5000
JWT_SECRET=your-secret-key

4️⃣ Run the Server

node server.js

The backend will run on http://localhost:5000

5️⃣ Start the Frontend

cd frontend
npm start

The frontend will run on http://localhost:3000

🌍 Deployment

Frontend:

Deployed using GitHub Pages / Vercel

Frontend URL: https://your-username.github.io/LearnHub/

Backend:

Deployed using Render

Backend URL: https://learnhub.onrender.com

📜 API Endpoints

Method

Endpoint

Description

GET

/api/courses

Fetch all courses

GET

/api/courses/:id

Fetch a single course

POST

/api/signup

Register a new user

POST

/api/login

Authenticate user

📷 Screenshots



🙌 Contributing

Fork the repo

Clone it locally: git clone https://github.com/your-username/LearnHub.git

Create a new branch: git checkout -b feature-name

Commit your changes: git commit -m "Added a new feature"

Push the branch: git push origin feature-name

Submit a Pull Request

📩 Contact

For queries, contact Your Name or visit the GitHub Repo

🎓 Happy Learning! 🚀