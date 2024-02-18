import { Router } from "express";
import * as userController from "../controllers/webUserController";
import upload from "../middlewares/multer";
import allowOnlyLoggedInUser from "../middlewares/userAuth";
const webUserRouter: Router = Router();

webUserRouter
  .post("/login", userController.loginUser)
  .post(
    "/register",
    upload.single("profilePicture"),
    userController.registerUser
  )
  .post(
    "/sendVerificationMail",
    upload.single("profilePicture"),
    userController.sendVerificationMail
  )
  .post("/sendMail", userController.sendMail)
  .post("/verifyOtp", userController.verifyOtp)
  .post("/resetPassword", userController.resetPassword)
  .get("/getUser", allowOnlyLoggedInUser ,userController.getUser);

export default webUserRouter;
