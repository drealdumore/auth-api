export const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const NAME_REGEX = /^[a-zA-Z0-9 -]+$/;

export const PASSWORD_REGEX =
  /^(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-])(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9]).{8,20}$/;

export const MAX_FAILED_LOGIN_ATTEMPTS = 5;
export const ACCOUNT_LOCK_TIME_MINUTES = 15;

export const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
};
