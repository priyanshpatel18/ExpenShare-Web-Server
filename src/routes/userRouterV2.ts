import { Router } from "express";
import upload from "../middlewares/multer";
import { sessionMiddleware } from "../middlewares/session";
import allowOnlyLoggedInUser from "../middlewares/userAuth";
import * as userController from "../controllers/androidUserController";

const appRouter = Router();

appRouter.post("/login", userController.loginUser);

export default appRouter;
