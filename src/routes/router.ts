import { NextFunction, Request, Response, Router } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import multer from "multer";
import * as controller from "../controllers/controller";
import { User, UserDocument } from "../models/models";
const userRouter: Router = Router();
const transactionRouter: Router = Router();

// Middlewares

// User Authentication
async function allowOnlyLoggedInUser(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const { token } = req.cookies;

  // Verify Token or Check if Token Exist
  if (!getToken(token) || !token) {
    return res.status(501).send("You need to Login First");
  }

  // Decode the Token
  const decodedToken: string | JwtPayload | null = getToken(token);

  if (!decodedToken || typeof decodedToken === "string") {
    return res.status(401).send("Invalid token");
  }

  // Find User from the decoded Token using _id
  const email: string = decodedToken.email;
  const user: UserDocument | null = await User.findOne({ email });
  if (!user) {
    return res.status(401).send("You need to Login First");
  }

  // Set User in the request for the next API Call
  req.user = user;
  next();
}

const getToken = (token: string) => {
  if (!token) return null;
  return jwt.verify(token, String(process.env.SECRET_KEY));
};

// Multer Middleware

// Configure Storage Engine
const storage: multer.StorageEngine = multer.diskStorage({
  filename: function (req: Express.Request, file: Express.Multer.File, cb) {
    cb(null, `${Date.now()}_${file.originalname}`);
  },
});

// Create Middleware with the storage
const upload: multer.Multer = multer({ storage: storage });

// Router
userRouter
  .post("/login", controller.loginUser)
  .post("/register", upload.single("profilePicture"), controller.registerUser)
  .post(
    "/sendVerificationMail",
    upload.single("profilePicture"),
    controller.sendVerificationMail
  )
  .post("/sendMail", controller.sendMail)
  .post("/verifyOtp", controller.verifyOtp)
  .post("/resetPassword", controller.resetPassword)
  .get("/getUser", allowOnlyLoggedInUser, controller.getUser);

transactionRouter
  .post("/add", controller.addTransaction)
  .get("/getAll", allowOnlyLoggedInUser, controller.getAllTransactions);

export { userRouter, transactionRouter };
