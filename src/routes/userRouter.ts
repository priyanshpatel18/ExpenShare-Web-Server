import { Router } from "express";
import * as userController from "../controllers/userController";
import upload from "../middlewares/multer";
import { sessionMiddleware } from "../middlewares/session";
import allowOnlyLoggedInUser from "../middlewares/userAuth";
const userRouter: Router = Router();
const mailRouter: Router = Router();

mailRouter.use(sessionMiddleware);
mailRouter
  .post(
    "/register",
    upload.single("profilePicture"),
    userController.registerUser
  )
  .post("/sendMail", userController.sendMail)
  .post("/sendVerificationMail", userController.sendEmailVerificationMail)
  .post("/verifyOtp", userController.verifyOtp)
  .get("/getEmail", userController.getEmail);

userRouter
  .get("/", allowOnlyLoggedInUser, userController.getUser)
  .post("/login", userController.loginUser);
export { mailRouter, userRouter };
