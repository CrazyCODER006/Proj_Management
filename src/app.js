import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

//basic configuarations
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser())


//cors configurations
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "https://localhost:5173", //vite
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);


//import the routes
import healthCheckRouter from "./routes/healthcheck.routes.js";
import authRouter from "./routes/auth.routes.js";

app.use("/api/v1/healthcheck", healthCheckRouter);
app.use("/api/v1/auth", authRouter);

app.get("/", (req, res) => {
  res.send("welcome to basecampy");
});

export default app;
