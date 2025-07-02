class AppError extends Error {
  constructor(message, statusCode) {
    // Call the parent class constructor with the message
    super(message);

    // Custom properties for error handling
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
    this.isOperational = true; // Mark as known/operational error

    // Capture the stack trace, excluding constructor
    Error.captureStackTrace(this, this.constructor);
  }
}

export default AppError;
