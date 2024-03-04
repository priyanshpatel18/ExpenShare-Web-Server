import express, { Express } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import "dotenv/config";
import { MongoClient } from "mongodb";
import { createServer } from "http";
import { Server } from "socket.io";
import mongoose from "mongoose";
import cron from "node-cron";
import path from "path";
// File Imports
import * as socketController from "./controllers/socketControllers";
import {
    userRouter,
    transactionRouter,
    groupRouter,
    CustomSocket,
    authMibblewareForSocket,
} from "./routes/router";

// Creating Backend Application
const app: Express = express();
// Create a HTTP Server
const server = createServer(app);
// Create an IO Server
export const io = new Server(server, {
	cors: {
		origin: ["https://expenshare.vercel.app", "http://192.168.43.242:5173"],
	},
});

// Create an interface to define the email-to-socket mapping
interface EmailToSocketMap {
    [email: string]: string;
}

// Create an empty object to store the mapping between email and socket ID
export const emailToSocketMap: EmailToSocketMap = {};

// middleware to authenticate user on socket
io.use(authMibblewareForSocket);

io.on("connection", (socket: CustomSocket) => {
    console.log("User connected", socket.id);

    // Bind email to the socketId
    socket.on("login", () => {
        if (socket.user?.email) {
            emailToSocketMap[socket.user?.email] = socket.id;
            console.log(emailToSocketMap);
        } else {
            console.log("Invalid email:", socket.user?.email);
        }        
    });

    socket.on("getUsers", (filter: string) => {
        socketController.handleGetUsers(socket, filter);
    });

    socket.on("sendRequest", (data) => {
        socketController.handleSendRequest(socket, data);
    });

    socket.on("acceptRequest", (data) => {
        socketController.updateGroup(socket, data);
    });

    socket.on("addTransaction", (data) => {        
		socketController.updateGroup(socket, data);
	});

    socket.on("removeMember", (data) => {
        socketController.updateGroup(socket, data);
    });

    socket.on("disconnect", () => {
        socket.disconnect();
        console.log("user disconnected", socket.id);
    });
});

// Middlewares
app.use(
	cors({
		origin: ["https://expenshare.vercel.app", "http://192.168.43.242:5173"],
		methods: ["GET", "POST", "PUT", "DELETE"],
		credentials: true,
	}),
);
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("view-engine", "ejs");
app.set("views", path.resolve("./views"));

// Routes
app.use("/user", userRouter);
app.use("/transaction", transactionRouter);
app.use("/group", groupRouter);

// Database Cleanup
cron.schedule(
    "0 * * * *",
    async () => {
        console.log("Running Database cleanup job...");
        try {
            const client = await MongoClient.connect(process.env.DB_URL!);
            const db = client.db();
            const otpCollection = db.collection("otps");
            const userDataCollection = db.collection("userdatas");
            const now = new Date();

            await otpCollection.deleteMany({ expires: { $lt: now } });
            await userDataCollection.deleteMany({ expires: { $lt: now } });
            console.log("Expired Colections cleared successfully.");
            client.close();
        } catch (error) {
            console.error("Error clearing Expired Collection:", error);
        }
    },
    {
        scheduled: true,
        timezone: "Asia/Kolkata",
    }
);

// DB Connection
const PORT: number = 8080 | Number(process.env.PORT);
const DB_URL: string = String(process.env.DB_URL);

mongoose
    .connect(DB_URL)
    .then(() => {
        console.log("Database Connected");
        server.listen(PORT, "192.168.43.242", () => {
			console.log("Server Started");
		});
    })
    .catch((err) => {
        console.log(err);
    });
