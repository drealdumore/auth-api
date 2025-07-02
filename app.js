import express from "express";
import morgan from "morgan";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import ExpressMongoSanitize from "express-mongo-sanitize";
import xss from "xss-clean";
import hpp from "hpp";
import globalErrorHandler from "./controllers/error.js";
import AppError from "./utils/appError.js";
import compression from "compression";
import userRouter from "./routes/users.js";
import adminRouter from "./routes/admin.js";

const app = express();

// Parse incoming request data as JSON
app.use(express.json());

// CORS
app.use(cors(""));

// Set security HTTP headers
app.use(helmet());

// Log requests to the console in development mode
if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// API Rate limiting to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again in an hour!",
});

app.use("/api", limiter);

// Body parser, reading data from body into req.body
app.use(express.urlencoded({ extended: true }));

// Cookie parser, reading data from cookies into req.cookies
app.use(cookieParser());

// Data sanitization against NoSQL query injection
app.use(ExpressMongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(
  hpp({
    whitelist: ["sort", "page", "limit"],
  })
);

// Compress all HTTP responses
app.use(compression());

app.get("/ip", (req, res) => res.send(req.ip));
app.use("/api/users", userRouter);
app.use("/api/admin", adminRouter);

// HANDLE UNDEFINED ERRORS
app.all("*", (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

// GLOBAL ERROR HANDLER
app.use(globalErrorHandler);

export default app;
