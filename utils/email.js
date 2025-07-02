import nodemailer from "nodemailer";
import pug from "pug";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

class Email {
  constructor(user, payload) {
    this.from = process.env.FROM || "Auth API <no-reply@auth-api.com>";
    this.to = user.email;
    this.firstName = user.firstName || "User";
    this.payload = payload;
  }

  async newTransport() {
    const isProduction = process.env.NODE_ENV === "production";

    return nodemailer.createTransport({
      host: isProduction ? "smtp.gmail.com" : "smtp.ethereal.email",
      port: 587,
      secure: false,
      auth: {
        user: isProduction
          ? process.env.GOOGLE_USERNAME
          : process.env.ETHEREAL_USERNAME,
        pass: isProduction
          ? process.env.GOOGLE_PASSCODE
          : process.env.ETHEREAL_PASSWORD,
      },
      tls: isProduction ? { rejectUnauthorized: false } : undefined,
    });
  }

  async sendEmail(template, subject, customTo = null) {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);

    const html = pug.renderFile(
      join(__dirname, `../views/email/${template}.pug`),
      {
        firstName: this.firstName,
        payload: this.payload,
        subject,
      }
    );

    const mailOptions = {
      from: this.from,
      to: customTo || this.to,
      subject,
      html,
    };

    const transporter = await this.newTransport();
    await transporter.sendMail(mailOptions);
  }

  async sendWelcomeEmail() {
    await this.sendEmail("welcome", "Welcome to Auth API! 👋");
  }

  async sendForgotPassword() {
    await this.sendEmail("forgotPassword", "Reset your password - Auth API");
  }

  async sendOtp() {
    await this.sendEmail("otpRequest", "Your Auth API OTP Code");
  }

  async sendEmailVerificationCode() {
    await this.sendEmail("emailVerification", "Verify your Auth API email");
  }

  async sendEmailVerificationCodeToPendingEmail(newEmail) {
    await this.sendEmail(
      "emailVerification",
      "Verify your new email address",
      newEmail
    );
  }
}

export default Email;
