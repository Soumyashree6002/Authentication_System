Flask Authentication System

Overview

This is a user authentication system built using Flask and SQLAlchemy. It provides features such as user registration, login, session management, password reset, and rate-limiting for security. The application also enforces strong password policies.

Features

User Registration with email and phone number validation.

Secure password hashing using bcrypt.

Login system with session handling.

Dashboard access only for authenticated users.

Rate limiting (5 login attempts per minute) using Flask-Limiter.

Password reset functionality with email and phone number confirmation.

Enforced strong password policy (must include alphabets, numbers, and special characters).

Technologies Used

Flask (Web framework)

Flask-SQLAlchemy (Database ORM)

bcrypt (Password hashing)

Flask-Limiter (Rate limiting)

Flask-Session (Session management)

SQLite (Default database, configurable via environment variables)

Jinja2 (Templating engine)

Dotenv (For environment variable management)


Usage

Register: Navigate to /register and create an account.

Login: Use /login with your registered email and password.

Dashboard: After logging in, you will be redirected to /dashboard.

Logout: Click the logout button or visit /logout.

Forgot Password: Use /confirm to verify your email and phone number, then reset your password at /forgot.


Security Measures

Password Hashing: All passwords are securely hashed using bcrypt before storing in the database.

Rate Limiting: Login attempts are limited to 5 per minute to prevent brute-force attacks.

Session Expiry: Persistent sessions expire after 7 days.

Input Validation: Ensures strong passwords and prevents duplicate registrations.

