# SECRETS WEB APPLICATION

A full-stack web application that allows users to securely store their personal secrets online.  
Each user can register, log in, and manage (add, view, edit, delete) their own secrets privately.  
The application ensures that secrets are not shared across users and supports secure user authentication.

## Features

- User authentication with session management  
- Create, view, edit, and delete secrets  
- Each user can manage their own secrets only  
- Passwords are securely hashed  
- User-friendly UI with responsive design  
- MongoDB Atlas integration for cloud-based data storage

## Tech Stack

- **Frontend:** HTML, CSS, EJS (Embedded JavaScript)  
- **Backend:** Node.js, Express.js  
- **Database:** MongoDB (Mongoose)  
- **Authentication:** Passport.js (Local Strategy), express-session, bcrypt  
- **Deployment:** Render

## Deployment

**Live Application:** [Click Here to View](https://secrets-nhs9.onrender.com)  


## Installation and Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/secrets-web-app.git
   cd secrets-web-app
Install dependencies

bash
Copy
Edit
npm install
Set up environment variables
Create a .env file in the root directory and add the following:

ini
Copy
Edit
SESSION_SECRET=yourSessionSecret
MONGODB_URI=yourMongoDBAtlasConnectionString
Run the app

bash
Copy
Edit
node app.js
Visit http://localhost:3000 in your browser.

License
This project is licensed under the MIT License.

Acknowledgments
Node.js

Express.js

MongoDB

Mongoose

Passport.js

Render for deployment