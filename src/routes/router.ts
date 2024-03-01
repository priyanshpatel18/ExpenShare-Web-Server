import { NextFunction, Request, Response, Router } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import multer from "multer";
import * as controller from "../controllers/controller";
import { User, UserDocument } from "../models/models";
import { Socket } from "socket.io";
const userRouter: Router = Router();
const transactionRouter: Router = Router();
const groupRouter: Router = Router();
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
        return res.status(501).json({ message: "You need to Login First" });
    }

    // Decode the Token
    const decodedToken: string | JwtPayload | null = getToken(token);

    if (!decodedToken || typeof decodedToken === "string") {
        return res.status(401).json({ message: "Invalid token" });
    }

    // Find User from the decoded Token using _id
    const email: string = decodedToken.email;
    const user: UserDocument | null = await User.findOne(
        { email },
        { password: 0 }
    );
    if (!user) {
        return res.status(401).json({ message: "You need to Login First" });
    }

    // Set User in the request for the next API Call
    req.user = user;
    next();
}

interface CustomSocket extends Socket {
    user?: any;
}

// User Authentication middleware for socket
export async function authMibblewareForSocket(
    socket: CustomSocket,
    next: (err?: any) => void
) {
    const token = socket.handshake.query.token;

    // Verify Token or Check if Token Exist
    if (!token) {
        return next(new Error("You need to login first"));
    }

    // Decode the Token
    const decodedToken = getToken(token as string);

    if (!decodedToken || typeof decodedToken === "string") {
        return next(new Error("Invalid token"));
    }

    // Find User from the decoded Token using email
    const email = decodedToken.email;
    const user = await User.findOne({ email }, { password: 0 });

    if (!user) {
        return next(new Error("You need to login first"));
    }

    // Set User in the socket for the next event handling
    socket.user = user;
    next();
}

const getToken = (token: string) => {
    try {
        return jwt.verify(token, String(process.env.SECRET_KEY));
    } catch (error) {
        console.error("Error verifying token");
        return null;
    }
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
    .get(
        "/notifications",
        allowOnlyLoggedInUser,
        controller.getAllNotifications
    )
    .get("/getAllUsers", allowOnlyLoggedInUser, controller.getAllUsers)
    .get("/getUser", allowOnlyLoggedInUser, controller.getUser)
    .post("/handleRequest", allowOnlyLoggedInUser, controller.handleRequest)
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
    .post("/logout", controller.logoutUser)
    .put(
        "/update",
        allowOnlyLoggedInUser,
        upload.single("profilePicture"),
        controller.updateUser
    )
    .delete("/delete", allowOnlyLoggedInUser, controller.deleteUser);

transactionRouter
    .post(
        "/add",
        allowOnlyLoggedInUser,
        upload.single("invoiceUrl"),
        controller.addTransaction
    )
    .get("/getAll", allowOnlyLoggedInUser, controller.getAllTransactions)
    .put(
        "/update/:transactionId",
        allowOnlyLoggedInUser,
        controller.editTransaction
    )
    .delete(
        "/delete/:transactionId",
        allowOnlyLoggedInUser,
        controller.deleteTransaction
    );

groupRouter
    .post("/removeMember", allowOnlyLoggedInUser, controller.removeMember)
    .post(
        "/create",
        allowOnlyLoggedInUser,
        upload.single("groupProfile"),
        controller.createGroup
    )
    .get("/getAll", allowOnlyLoggedInUser, controller.getAllGroups)
    .post(
        "/create",
        allowOnlyLoggedInUser,
        upload.single("groupProfile"),
        controller.createGroup
    )
    .get("/getAll", allowOnlyLoggedInUser, controller.getAllGroups)
    .get("/:groupId", allowOnlyLoggedInUser, controller.getselectedlGroup);

export { userRouter, transactionRouter, groupRouter, CustomSocket };
