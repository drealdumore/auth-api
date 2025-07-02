# Simple Authentication api

## Overview

This is a simple authentication api that provides features for user authentication, user management, and email notifications.

## Features

- **User Management**: Sign up, log in, update profile, and manage user accounts.
- **Authentication**: Secure user authentication with JWT and refresh tokens.
- **Email Notifications**: Send emails for account verification, password reset, and OTP requests.
- **Error Handling**: Centralized error handling for API responses.

## Technologies Used

- **Backend**: Node.js, Express.js
- **Database**: MongoDB, Mongoose
- **Templating Engine**: Pug
- **Email Service**: Nodemailer
- **Security**: Helmet, express-rate-limit, xss-clean, express-mongo-sanitize

## Project Structure

```
Auth API/
├── app.js                # Main application file
├── server.js             # Server setup
├── package.json          # Project dependencies and scripts
├── controllers/          # Application controllers
├── models/               # Mongoose models
├── routes/               # API routes
├── helpers/              # Helpers
├── utils/                # Utility functions and classes
├── views/                # Email templates
└── .gitignore            # Ignored files and folders
```

## Installation

1. Clone the repository:
   ```bash
   git clone auth-api
   ```
2. Navigate to the project directory:
   ```bash
   cd auth-api
   ```
3. Install dependencies:
   ```bash
   pnpm install
   ```
4. Create a `.env` file in the root directory and configure the following environment variables:
   ```env
   NODE_ENV=development
   PORT=8000
   LOCALDB=<your-local-mongodb-uri>
   DB=<your-production-mongodb-uri>
   JWT_SECRET=<your-jwt-secret>
   JWT_EXPIRES_IN=<jwt-expiration-time>
   JWT_REFRESH_SECRET=<your-refresh-token-secret>
   JWT_REFRESH_SECRET_EXPIRES_IN=<refresh-token-expiration-time>
   JWT_COOKIE_EXPIRES_IN=<jwt-cookie-expiration-time>
   JWT_REFRESH_COOKIE_EXPIRES_IN=<refresh-cookie-expiration-time>
   GOOGLE_USERNAME=<your-gmail-username>
   GOOGLE_PASSCODE=<your-gmail-passcode>
   ETHEREAL_USERNAME=<your-ethereal-username>
   ETHEREAL_PASSWORD=<your-ethereal-password>
   FROM=<email-sender-name>
   ```

## Usage

1. Start the development server:
   ```bash
   pnpm dev
   ```
2. For production:
   ```bash
   pnpm prod
   ```
3. Access the application at `http://localhost:8000`.

## API Endpoints

### User Routes

- `POST /api/users/register`: Sign up a new user.
- `POST /api/users/login`: Log in a user.
- `POST /api/users/logout`: Log out the current user.
- `POST /api/users/forgotPassword`: Request a password reset link.
- `PATCH /api/users/resetPassword/:token`: Reset password using the reset token.
- `POST /api/users/sendEmailVerificationCode`: Send an email verification code to the user’s email.
- `POST /api/users/verifyEmailCode`: Verify email with the code sent to email.
- `POST /api/users/refreshToken`: Refresh the access token using a refresh token.

- `GET /api/users/me`: Get the current user’s profile.
- `PATCH /api/users/updateMyPassword`: Update the current user’s password.
- `PATCH /api/users/updateMe`: Update the current user’s profile info.
- `PATCH /api/users/disableMe`: Disable the current user’s account (soft delete).
- `DELETE /api/users/deleteMe`: Permanently delete the current user’s account.

### Admin Routes

- `POST /api/admin/login`: Admin login (generates OTP for verification).
- `POST /api/admin/verifyOtp`: Verify admin OTP sent via email.
- `POST /api/admin/createAdmin`: Create a new admin user.
- `GET /api/admin/getAllUsers`: Get all active users.
- `GET /api/admin/getInactiveUsers`: Get all inactive users.
- `GET /api/admin/getUser/:id`: Get a user by ID.
- `PATCH /api/admin/updateUser/:id`: Update user details (emailVerified, active, role).
- `PATCH /api/admin/disableUser/:id`: Disable (deactivate) a user.
- `PATCH /api/admin/enableUser/:id`: Enable (reactivate) a user.
- `DELETE /api/admin/deleteUser/:id`: Delete a user.
- `DELETE /api/admin/deleteAllUsers`: Delete all users (use with caution).
- `POST /api/admin/refreshToken`: Refresh admin access token.

## License

This project is licensed under the ISC License.

## Author

Samuel Isah
