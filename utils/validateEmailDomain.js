import fs from "fs";
import path from "path";
import AppError from "./appError.js";

// Load invalid domains once at startup
const invalidDomains = JSON.parse(
  fs.readFileSync(path.resolve("./domains.json"), "utf-8")
);

// This function now throws an error instead of calling next()
export const validateEmailDomain = (email) => {
  const emailDomain = email.split("@")[1];

  if (invalidDomains.includes(emailDomain)) {
    throw new AppError("Email domain not allowed!", 401);
  }
};
