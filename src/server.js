import "dotenv/config";
import express from "express";
import cors from "cors";
import { corsOptions } from "./config/corsOptions.js";
import morgan from "morgan";
import userRoutes from "./routes/user.route.js";
import passport from "passport";
import "./config/passportJWT.config.js";

const app = express();

// middleware
app.use(cors(corsOptions));
app.use(express.json());

app.use(morgan("dev")); // for request logs output

app.use(passport.initialize()); // Initialize passport middleware

app.get("/", async (req, res) => {
  return res.json({ success: true, message: "user created successfully" });
});

//rotues
app.use("/api/v1/users", userRoutes);

//page not found
app.use("*", (req, res) => {
  res.status(404).send("Not Found");
});

// catch all error (including custom throw errors)
app.use((error, req, res, next) => {
  console.log("//Error handler: \n", error);
  res.status(error.statusCode || 500).json({
    success: false,
    message: error.message || "Something went wrong",
  });
  next();
});

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log(`Server is running in PORT: ${PORT}`);
});
