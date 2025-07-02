import asyncHandler from "express-async-handler";
import User from "../models/User.js";
import AppError from "../utils/appError.js";
import Email from "../utils/email.js";

// Send Email Verification Code
export const sendEmailVerificationCode = asyncHandler(
  async (req, res, next) => {
    const { email } = req.body;

    if (!email) {
      return next(new AppError("Email is required.", 400));
    }

    const normalizedEmail = email.toLowerCase();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return next(new AppError("No user found with this email address.", 404));
    }

    // Prevent spamming - Allow new code only if old one is expired or not sent recently
    if (
      user.emailVerificationExpires &&
      user.emailVerificationExpires > Date.now()
    ) {
      return next(
        new AppError(
          "Please wait before requesting another verification code.",
          429
        )
      );
    }

    const verificationCode = user.createEmailVerificationCode();
    user.emailVerificationExpires = Date.now() + 10 * 60 * 1000; // 10 minutes expiry
    await user.save({ validateBeforeSave: false });

    try {
      const emailSender = new Email(user, verificationCode);
      await emailSender.sendEmailVerificationCode();

      res.status(200).json({
        status: "success",
        message: "Verification code sent to email successfully.",
      });
    } catch (err) {
      console.error("Email send failed:", err);
      return next(new AppError("Failed to send verification email.", 500));
    }
  }
);

// Verify Email Code
export const verifyEmailCode = asyncHandler(async (req, res, next) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return next(new AppError("Email and code are required.", 400));
  }

  const normalizedEmail = email.toLowerCase();
  const user = await User.findOne({ email: normalizedEmail });

  if (!user) {
    return next(new AppError("No user found with this email address.", 404));
  }

  const isCodeInvalid =
    code !== user.emailVerificationCode ||
    !user.emailVerificationExpires ||
    user.emailVerificationExpires < Date.now();

  if (isCodeInvalid) {
    return next(new AppError("Invalid or expired verification code.", 400));
  }

  user.emailVerified = true;
  user.emailVerificationCode = undefined;
  user.emailVerificationExpires = undefined;
  await user.save({ validateBeforeSave: false });

  try {
    const payload = `${req.protocol}://${req.get("host")}/me`;
    const emailSender = new Email(user, payload);
    await emailSender.sendWelcomeEmail();

    res.status(200).json({
      status: "success",
      message: "Email verified successfully. Welcome email sent.",
    });
  } catch (err) {
    console.error("Welcome email failed:", err);
    return next(
      new AppError("Email verified, but failed to send welcome email.", 500)
    );
  }
});
