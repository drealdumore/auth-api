import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import { promisify } from "util";
import AppError from "../utils/appError.js";
import Token from "../models/Token.js";
import User from "../models/User.js";
import { COOKIE_OPTIONS } from "../utils/validation.js";

// Sign Access Token
export const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

// Sign Refresh Token
export const signRefreshToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_SECRET_EXPIRES_IN,
  });
};

// Refresh Token Logic
export const refreshAccessToken = asyncHandler(async (req, res, next) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return next(
      new AppError("Refresh token not found. Please log in again.", 401)
    );
  }

  let decoded;
  try {
    decoded = await promisify(jwt.verify)(
      refreshToken,
      process.env.JWT_REFRESH_SECRET
    );
  } catch (err) {
    return next(
      new AppError(
        "Invalid or expired refresh token. Please log in again.",
        401
      )
    );
  }

  const storedToken = await Token.findOne({ token: refreshToken });
  if (!storedToken) {
    return next(
      new AppError("Refresh token is invalid or has been revoked.", 401)
    );
  }

  const user = await User.findById(decoded.id);
  if (!user) {
    return next(new AppError("User no longer exists.", 401));
  }

  const newAccessToken = signToken(user._id);
  const newRefreshToken = signRefreshToken(user._id);

  storedToken.token = newRefreshToken;
  await storedToken.save();

  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    expires: new Date(
      Date.now() +
        process.env.JWT_REFRESH_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
  });

  res.status(200).json({
    status: "success",
    accessToken: newAccessToken,
  });
});

// Send Access + Refresh Tokens
export const createAndSendTokens = async (user, statusCode, req, res) => {
  const accessToken = signToken(user._id);
  const refreshToken = signRefreshToken(user._id);

  res.cookie("jwt", accessToken, {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers["x-forwarded-proto"] === "https",
  });

  res.cookie("refreshToken", refreshToken, {
    ...COOKIE_OPTIONS,
    expires: new Date(
      Date.now() +
        process.env.JWT_REFRESH_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
  });

  await Token.create({ token: refreshToken, user: user._id });
  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    accessToken,
    refreshToken,
    data: { user },
  });
};
