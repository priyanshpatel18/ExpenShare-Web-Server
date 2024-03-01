import bcrypt from "bcrypt";
import { UploadApiResponse, v2 as cloudinary } from "cloudinary";
import ejs from "ejs";
import { Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { Types } from "mongoose";
import nodemailer from "nodemailer";
import SMTPTransport from "nodemailer/lib/smtp-transport";
import otpGenerator from "otp-generator";
import path from "path";
import {
    History,
    MonthlyHistoryDocument,
    OTP,
    OTPDocument,
    Transaction,
    TransactionDocument,
    User,
    UserData,
    UserDataDocument,
    UserDocument,
    GroupDocument,
    Group,
    GroupRequest,
    GroupUserDocument,
    GroupUser,
} from "../models/models";
import { emailToSocketMap, io } from "..";

interface User {
    email: string;
    userName: string;
}

interface UserData {
    email: string;
    userName: string;
    password: string;
    profilePicture?: string | undefined;
}

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET_KEY,
});

const setToken = (user: User) => {
    return jwt.sign(
        {
            email: user.email,
            userName: user.userName,
        },
        String(process.env.SECRET_KEY),
        {
            expiresIn: "7d",
        }
    );
};

export const getToken = (token: string) => {
    if (!token) return null;
    return jwt.verify(token, String(process.env.SECRET_KEY));
};

export const setUserData = (user: UserData) => {
    return jwt.sign(
        {
            email: user.email,
            userName: user.userName,
            password: user.password,
            profilePicuture: user.profilePicture,
        },
        String(process.env.SECRET_KEY),
        {
            expiresIn: "1h",
        }
    );
};

// POST : /user/register
export const registerUser = async (req: Request, res: Response) => {
    try {
        // Get userData from Cookies
        const { userDataId } = req.cookies;

        const userData: UserDataDocument | null = await UserData.findById({
            _id: userDataId,
        });

        if (!userData) {
            return res.status(401).json({ message: "User Data Expired" });
        }

        // Destructure the Decoded User
        let { email, userName, password, profilePicture } = userData!;

        email = email.toLowerCase();
        userName = userName.toLowerCase();

        // Upload Profile Picture if exist
        let profileUrl = "";
        let publicId = "";

        if (profilePicture) {
            const result: UploadApiResponse = await cloudinary.uploader.upload(
                profilePicture,
                {
                    folder: "uploads",
                }
            );
            profileUrl = result.secure_url;
            publicId = result.public_id;
        }

        // Create User
        User.create({
            email: email,
            userName: userName,
            profilePicture: profileUrl,
            publicId,
            password: password,
        });

        // Encode the Token and Set it in the Cookies
        const token: string = setToken({
            email: email as string,
            userName: userName as string,
        });
        res.cookie("token", token, {
            // httpOnly: true,
            // secure: true,
            // sameSite: "none",
        });
        // Clear userDataId & email from cookies
        res.clearCookie("userDataId");
        res.clearCookie("email");
        await UserData.deleteOne({ _id: userDataId });
        res.status(200).json({ message: "User registered successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

// POST: /user/login
export const loginUser = async (req: Request, res: Response) => {
    let { userNameOrEmail, password } = req.body;

    userNameOrEmail = userNameOrEmail.toLowerCase();

    try {
        const user: UserDocument | null = await User.findOne({
            $or: [{ email: userNameOrEmail }, { userName: userNameOrEmail }],
        });

        // Check if User Exist or not
        if (!user) {
            return res
                .status(401)
                .json({ message: "You need to Register First" });
        }

        // Comapre the Password using bcrypt
        const passwordMatch: boolean = await bcrypt.compare(
            password,
            user.password
        );
        if (!passwordMatch) {
            res.status(501).json({ message: "Incorrect Password" });
            return;
        } else {
            // Set Token in Cookies if Password is correct
            const token: string = setToken(user);
            res.cookie("token", token, {
                // httpOnly: true,
                // secure: true,
                // sameSite: "none",
            });
            res.status(201).json({ message: "Login Successfully" });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

// POST: /user/sendVerificationMail
export const sendVerificationMail = async (req: Request, res: Response) => {
    const { email, userName, password } = req.body;
    const profilePicture: string | undefined = req.file?.path;

    const user: UserDocument | null = await User.findOne({
        $or: [{ email: email }, { userName: userName }],
    });
    // Check for unique Email
    if (user?.email === email) {
        return res.status(400).json({ message: "Email should be unique" });
    }
    // Check for unique userName
    if (user?.userName === userName) {
        return res.status(400).json({ message: "Username should be unique" });
    }

    // Generate OTP
    const otp: string = otpGenerator.generate(6, {
        lowerCaseAlphabets: false,
        upperCaseAlphabets: false,
        specialChars: false,
    });

    // Render EJS Template
    const templatePath: string = path.resolve(
        __dirname,
        "../views/mailFormat.ejs"
    );
    const htmlContent: string = await ejs.renderFile(templatePath, { otp });

    // Send Email
    const mailOptions = {
        from: String(process.env.USER),
        to: email,
        subject: "Email Verification",
        html: htmlContent,
    };

    const transporter: nodemailer.Transporter<SMTPTransport.SentMessageInfo> =
        nodemailer.createTransport({
            service: "gmail",
            host: String(process.env.SMTP_HOST),
            port: Number(process.env.SMTP_PORT),
            secure: true,
            auth: {
                user: process.env.USER,
                pass: process.env.PASS,
            },
        });

    try {
        await transporter.sendMail(mailOptions);

        // Hash OTP and save it in the database
        const salt: string = await bcrypt.genSalt(10);
        const hashedOtp: string = await bcrypt.hash(otp, salt);

        const otpDocument: OTPDocument = await OTP.create({
            otp: hashedOtp,
            email: email,
        });

        // Set the Registration Data in Token
        const userData = {
            email: email as string,
            userName: userName as string,
            password: password as string,
            profilePicture: profilePicture as string,
        };
        const UserDataDocument: UserDataDocument = await UserData.create(
            userData
        );

        // Set the User Data Id in the Cookies
        res.cookie("userDataId", UserDataDocument._id, {
            // httpOnly: true,
            // secure: true,
            // sameSite: "none",
        });
        // Set the OTP ID in the cookies
        res.cookie("otpId", otpDocument._id, {
            // httpOnly: true,
            // secure: true,
            // sameSite: "none",
        });
        res.status(200).json({ message: "OTP Sent Successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
};

// POST: /user/verifyOtp
export const verifyOtp = async (req: Request, res: Response) => {
    const { userOtp } = req.body;
    const { otpId } = req.cookies;

    // Verify OTP
    try {
        // Find the OTP document in the database by its ID
        const otp: OTPDocument | null = await OTP.findById(otpId);

        // Check if the OTP document exists
        if (!otp) {
            return res.status(404).json({ message: "OTP not found" });
        }

        // Compare the user-provided OTP with the OTP from the database
        const isVerified: boolean = await bcrypt.compare(userOtp, otp.otp);

        if (!isVerified) {
            return res.status(401).json({ message: "Incorrect OTP" });
        }

        // Set Email in the cookies
        res.cookie("email", otp.email, {
            // httpOnly: true,
            // secure: true,
            // sameSite: "none",
        });
        // Clear Cookie and delete the OTP from the database
        res.clearCookie("otpId");
        await OTP.deleteOne({ _id: otpId });

        return res.sendStatus(200);
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

// POST : /user/sendMail
export const sendMail = async (req: Request, res: Response) => {
    const { email } = req.body;

    const user: UserDocument | null = await User.findOne({ email });

    if (!user) {
        return res.status(400).json({ message: "Email doesn't exist" });
    }

    // Generate OTP
    const otp: string = otpGenerator.generate(6, {
        lowerCaseAlphabets: false,
        upperCaseAlphabets: false,
        specialChars: false,
    });

    // Render EJS Template
    const templatePath: string = path.resolve(
        __dirname,
        "../views/mailFormat.ejs"
    );
    const htmlContent: string = await ejs.renderFile(templatePath, { otp });

    // Send Email
    const mailOptions = {
        from: String(process.env.USER),
        to: email,
        subject: "OTP Verification",
        html: htmlContent,
    };

    const transporter: nodemailer.Transporter<SMTPTransport.SentMessageInfo> =
        nodemailer.createTransport({
            service: "gmail",
            host: String(process.env.SMTP_HOST),
            port: Number(process.env.SMTP_PORT),
            secure: true,
            auth: {
                user: process.env.USER,
                pass: process.env.PASS,
            },
        });

    try {
        await transporter.sendMail(mailOptions);

        // Hash OTP and save it in the database
        const salt: string = await bcrypt.genSalt(10);
        const hashedOtp: string = await bcrypt.hash(otp, salt);

        const otpDocument: OTPDocument = await OTP.create({
            otp: hashedOtp,
            email: email,
        });

        // Set the OTP ID in the cookies
        res.cookie("otpId", otpDocument._id, {
            // httpOnly: true,
            // secure: true,
            // sameSite: "none",
        });
        res.status(200).json({ message: "OTP Sent Successfully" });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal Server Error" });
    }
};

// POST : /user/resetPassword
export const resetPassword = async (req: Request, res: Response) => {
    const { password } = req.body;
    let { email } = req.cookies;

    if (!email && req.cookies.token) {
        const decoded = jwt.decode(req.cookies.token) as JwtPayload;
        email = decoded?.email;
    }

    if (!email) {
        return res.status(400).json({ message: "Internal Server Error" });
    }

    try {
        const user: UserDocument | null = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: "User not Found" });
        }

        user.password = password;
        user.save();
        res.clearCookie("email");
        res.status(200).json({ message: "Password updated" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

// GET: /user/getUser
export const getUser = (req: Request, res: Response) => {
    const user: UserDocument = req.user;

    try {
        const userObject = {
            email: user.email,
            userName: user.userName,
            profilePicture: user.profilePicture,
            totalBalance: user.totalBalance,
            totalIncome: user.totalIncome,
            totalExpense: user.totalExpense,
        };

        return res.status(200).json({ userObject });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error" });
    }
};

// POST: /transaction/add
export const addTransaction = async (req: Request, res: Response) => {
    const {
        type,
        transactionAmount,
        category,
        transactionTitle,
        notes,
        transactionDate,
    } = req.body;
    const invoice: string | undefined = req.file?.path;
    const user = req.user;

    if (!user) {
        return res.status(401).json({ message: "User not Found" });
    }

    let invoiceUrl: string = "";
    let publicId: string = "";

    if (invoice) {
        const result = await cloudinary.uploader.upload(invoice, {
            folder: "invoices",
        });

        invoiceUrl = result.secure_url;
        publicId = result.public_id;
    }

    try {
        const transactionObject = {
            transactionAmount: String(transactionAmount),
            category: String(category).toLocaleUpperCase(),
            transactionTitle: String(transactionTitle),
            notes: String(notes),
            invoiceUrl,
            publicId,
            transactionDate: String(transactionDate),
            type: type,
            createdBy: new Types.ObjectId(user._id),
        };

        const transactionDocument: TransactionDocument =
            await Transaction.create(transactionObject);

        const transactionId = new Types.ObjectId(transactionDocument._id);

        const dateForm = new Date(transactionDate);

        const transactionMonth = dateForm.getMonth();
        const transactionYear = dateForm.getFullYear();

        const monthlyHistory: MonthlyHistoryDocument | null =
            await History.findOneAndUpdate(
                {
                    user: user._id,
                    month: transactionMonth,
                    year: transactionYear,
                },
                {
                    $inc: {
                        income:
                            type === "income" ? Number(transactionAmount) : 0,
                        expense:
                            type === "expense" ? Number(transactionAmount) : 0,
                    },
                },
                { upsert: true, new: true }
            );

        if (monthlyHistory) {
            monthlyHistory.transactionIds.push(transactionId);
            monthlyHistory.monthlyBalance =
                monthlyHistory.income - monthlyHistory.expense;
            await monthlyHistory.save();
        }

        if (type === "income") {
            user.incomes.push(transactionId);
            user.totalBalance += Number(transactionAmount);
            user.totalIncome += Number(transactionAmount);
            // Add to History
        } else if (type === "expense") {
            user.expenses.push(transactionId);
            user.totalBalance -= Number(transactionAmount);
            user.totalExpense += Number(transactionAmount);
        }
        await user.save();

        return res.sendStatus(200);
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

// GET: /transaction/getAll
export const getAllTransactions = async (req: Request, res: Response) => {
    const user = req.user;

    try {
        if (!user) {
            return res.status(401).json({ message: "User not Found" });
        }

        const transactions: TransactionDocument[] | null =
            await Transaction.find({
                createdBy: user._id,
            });

        return res.status(200).json({ transactions });
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

// POST : /user/logout
export const logoutUser = async (req: Request, res: Response) => {
    try {
        res.clearCookie("token", {
            // httpOnly: true,
            // secure: true,
            // sameSite: "none",
        });
        return res.status(200).json({ message: "Logged out" });
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

// PUT: /user/update Update User
export const updateUser = async (req: Request, res: Response) => {
    const profilePicture = req.file?.path;
    const { userName } = req.body;
    const { email } = req.user;

    try {
        const user: UserDocument | null = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: "User not found" });
        }

        if (userName) {
            user.userName = userName;
        }
        if (user.publicId.includes("uploads") && profilePicture) {
            cloudinary.uploader.destroy(user.publicId, (error) => {
                if (error) {
                    console.log(error);
                }
            });
        }

        let profileUrl: string = "";
        let publicId: string = "";

        if (profilePicture && user) {
            const result: UploadApiResponse = await cloudinary.uploader.upload(
                profilePicture,
                {
                    folder: "uploads",
                }
            );

            profileUrl = result.secure_url;
            publicId = result.public_id;

            user.profilePicture = profileUrl;
            user.publicId = publicId;
        }
        await user.save();

        res.status(200).json({ message: "User Updated Successfully" });
    } catch (error: any) {
        if (
            error.code === 11000 &&
            error.keyPattern &&
            error.keyPattern.userName
        ) {
            return res
                .status(401)
                .json({ message: "Username should be unique" });
        }
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

// DELETE : user/delete
export const deleteUser = async (req: Request, res: Response) => {
    const { email } = req.user;
    const user = req.user as UserDocument;

    try {
        const deletedUser = await User.findOneAndDelete({ email });
        await Transaction.deleteMany({ createdBy: user._id });
        await History.deleteMany({ user: user._id });

        if (!deletedUser) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ message: "User deleted successfully" });
    } catch (error) {
        return res.status(500).json({ message: "Internal Server Error" });
    }
};

//UPDATE: /transaction/update/:transactionId

export const editTransaction = async (req: Request, res: Response) => {
    try {
        const { transactionId } = req.params;
        const { transactionAmount, category, transactionTitle, notes } =
            req.body;

        // Find the transaction by its ID
        const transaction = await Transaction.findById(transactionId);
        if (!transaction) {
            return res.status(404).json({ message: "Transaction not found" });
        }

        // Calculate the difference in transaction amount and category
        const amountDifference =
            Number(transactionAmount) - Number(transaction.transactionAmount);
        const categoryDifference = category == transaction.category;

        // Update the transaction details
        transaction.transactionAmount = transactionAmount;
        transaction.category = category;
        transaction.transactionTitle = transactionTitle;
        transaction.notes = notes;
        await transaction.save();

        // Update user's history and balance
        const user: UserDocument = req.user;
        const history = await History.findOne({ user: user._id });
        if (!history) {
            return res.status(404).json({ message: "User history not found" });
        }

        // Update monthly balance
        history.monthlyBalance += amountDifference;

        // Update income and expense based on category difference
        if (categoryDifference) {
            if (transaction.type === "income") {
                history.income -= Number(transaction.transactionAmount);
                history.income += Number(transactionAmount);
            } else if (transaction.type === "expense") {
                history.expense -= Number(transaction.transactionAmount);
                history.expense += Number(transactionAmount);
            }
        }

        await history.save();

        // Update total balance
        user.totalBalance += amountDifference;
        if (categoryDifference) {
            if (transaction.type === "income") {
                user.totalIncome -= Number(transaction.transactionAmount);
                user.totalIncome += Number(transactionAmount);
            } else if (transaction.type === "expense") {
                user.totalExpense -= Number(transaction.transactionAmount);
                user.totalExpense += Number(transactionAmount);
            }
        }

        await user.save();

        res.status(200).json({
            message: "Transaction details updated successfully",
        });
    } catch (error) {
        console.error("Error editing transaction:", error);
        res.status(500).json({ message: "Internal server error" });
    }
};

// DELETE: /transaction/delete/:transactionId
export const deleteTransaction = async (req: Request, res: Response) => {
    try {
        const { transactionId } = req.params;
        const user = req.user as UserDocument;

        // Find the transaction to delete
        const transactionToDelete = await Transaction.findById(transactionId);

        if (!transactionToDelete) {
            return res.status(404).json({ message: "Transaction not found" });
        }

        // Check if the transaction belongs to the logged-in user
        if (!transactionToDelete.createdBy.equals(user._id)) {
            return res.status(403).json({
                message: "You are not authorized to delete this transaction",
            });
        }

        // Update user's balance based on transaction type
        if (transactionToDelete.type === "income") {
            user.totalBalance -= parseFloat(
                transactionToDelete.transactionAmount
            );
            user.totalIncome -= parseFloat(
                transactionToDelete.transactionAmount
            );
        } else {
            user.totalBalance += parseFloat(
                transactionToDelete.transactionAmount
            );
            user.totalExpense -= parseFloat(
                transactionToDelete.transactionAmount
            );
        }

        await user.save();

        // Delete the transaction
        await Transaction.findByIdAndDelete(transactionId);

        // Find the monthly history for this transaction
        const transactionDate = new Date(transactionToDelete.transactionDate);
        const transactionMonth = transactionDate.getMonth();
        const transactionYear = transactionDate.getFullYear();

        const monthlyHistory = await History.findOne({
            user: user._id,
            month: transactionMonth,
            year: transactionYear,
        });

        if (monthlyHistory) {
            monthlyHistory.transactionIds = monthlyHistory.transactionIds || [];
            // Remove the transaction ID from monthly history

            monthlyHistory.transactionIds =
                monthlyHistory.transactionIds.filter(
                    (id: Types.ObjectId) => !id.equals(transactionId)
                ) as [Types.ObjectId];
            // Recalculate the monthly balance
            monthlyHistory.monthlyBalance =
                monthlyHistory.income - monthlyHistory.expense;
            await monthlyHistory.save();
        }

        return res
            .status(200)
            .json({ message: "Transaction deleted successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error" });
    }
};

interface allUserObject {
    userName: string;
    email: string;
    profilePicture: string;
}

export const getAllUsers = async (req: Request, res: Response) => {
    try {
        const user: UserDocument | null = await User.findOne({ email: req.user.email });

        if (!user) {
            return res.status(401).json({ message: "User Not Found" });
        }

        const allUsers: UserDocument[] | null = await User.find({
            email: { $ne: user.email },
        });

        const userObject: allUserObject[] = [];

        if (allUsers) {
            allUsers.forEach((user) => {
                // Construct userObject
                const userData: allUserObject = {
                    userName: user.userName,
                    email: user.email,
                    profilePicture: user.profilePicture,
                };
                // Push userData into userObject array
                userObject.push(userData);
            });
        }

        res.status(200).json({ users: userObject });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
    }
};

// POST : /group/create
export const createGroup = async (req: Request, res: Response) => {
    const { groupName, category } = req.body;
    const groupProfile = req.file?.path;

    try {
        const user: UserDocument | null = await User.findOne({
            email: req.user.email,
        });

        if (!user) {
            return res.status(401).json({ message: "User Not Found" });
        }

        let profileUrl: string = "";
        let publicId: string = "";

        if (groupProfile) {
            const result: UploadApiResponse = await cloudinary.uploader.upload(
                groupProfile,
                {
                    folder: "uploads",
                }
            );
            profileUrl = result.secure_url;
            publicId = result.public_id;
        }

        const newGroup = {
            groupName,
            groupProfile: groupProfile ? profileUrl : "",
            publicId: publicId.trim() ? publicId : "",
            createdBy: new Types.ObjectId(user._id),
            members: [],
            groupExpense: [],
            totalExpense: 0,
            category: category,
        };

        const GroupDoc: GroupDocument = await Group.create(newGroup);

        user.groups.push(GroupDoc._id);
        await user.save();

        return res.status(200).json({ message: "Group Created" });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
    }
};

//GET :
export const getAllGroups = async (req: Request, res: Response) => {
    try {
        const user: UserDocument | null = await User.findOne({
            email: req.user.email,
        });

        if (!user) {
            return res.status(401).json({ message: "User Not Found" });
        }

        const groups: GroupDocument[] | null = await Group.find({
            _id: { $in: user.groups },
        });

        res.status(200).json({ groups });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
    }
};

// GET : /user/notifications
export const getAllNotifications = async (req: Request, res: Response) => {
	try {
		const user: UserDocument | null = await User.findOne({ email: req.user.email });

		if (!user) {
			return res.status(401).json({ message: "User Not Found" });
		}

		const requests = await GroupRequest.find({
			receiver: user._id,
			status: "PENDING",
		});

		const notifications = requests.map((request) => ({
			requestId: request._id,
			groupName: request.groupName,
			groupId: request.groupId,
		}));

		res.status(200).json({ notifications });
	} catch (error) {
		res.status(500).json({ message: "Internal Server Error" });
	}
};

// POST : /user/handleRequest
export const handleRequest = async (req: Request, res: Response) => {
	const { requestId, type } = req.body;

	try {
		const user: UserDocument | null = await User.findOne({ email: req.user.email });

		if (!user) {
			return res.status(401).json({ message: "User Not Found" });
		}

		const request = await GroupRequest.findById(requestId);

		if (!request) {
			return res.status(404).json({ message: "Request Not Found" });
		}

		const group: GroupDocument | null = await Group.findById(request.groupId);

		if (!group) {
			return res.status(404).json({ message: "Group doesn't exist" });
		}

		if (type === "accept" && request.receiver) {
			request.status = "ACCEPTED";
			group.members.push(request.receiver);
			user.groups.push(request.groupId);

			const existingGroupUser: GroupUserDocument | null = await GroupUser.findOne({
				email: user.email,
			});
			if (!existingGroupUser) {
				// Create a new GroupUser if it doesn't exist
				await GroupUser.create({
					_id: new Types.ObjectId(user._id),
					userId: new Types.ObjectId(user._id),
					email: user.email,
					userName: user.userName,
					profilePicture: user.profilePicture,
					expenses: [],
				});
			}
		} else if (type === "reject") {
			request.status = "REJECTED";
		}

		await user.save();
		await group.save();
		await request.save();

		return res.sendStatus(200);
	} catch (error) {
		console.error("Error handling request:", error);
		res.status(500).json({ message: "Internal Server Error" });
	}
};

// POST : /group/removeMember       
export const removeMember = async (req: Request, res: Response) => {
	const { memberEmail, groupId } = req.body;

	try {
		const user: UserDocument | null = await User.findOne({ email: req.user.email });

		if (!user) {
			return res.status(401).json({ message: "User Not Found" });
		}

		const group: GroupDocument | null = await Group.findById({ _id: groupId });

		if (!group) {
			return res.status(404).json({ message: "Group doesn't exist" });
		}

		const groupUser: GroupUserDocument | null = await GroupUser.findOne({
			email: memberEmail,
		});

		group.members = group.members.filter((member) => !member.equals(groupUser?._id));

		if (groupUser) {
			const member: UserDocument | null = await User.findOne({
				_id: groupUser.userId,
			});

			if (member) {
				member.groups = member.groups.filter((grpId) => !grpId.equals(groupId));
				await member.save();

				const socketId = emailToSocketMap[member.email];

				const data = {
					message: `You have been removed from ${group.groupName}`,
					groupId,
				};

				io.to(socketId).emit("removedMember", data);
			}
		}

		await group.save();

		return res.sendStatus(200);
	} catch (error) {
		console.error("Error handling request:", error);
		res.status(500).json({ message: "Internal Server Error" });
	}
};
export const getselectedlGroup = async (req: Request, res: Response) => {
    try {
        const user: UserDocument | null = await User.findOne({
            email: req.user.email,
        });

        if (!user) {
            return res.status(401).json({ message: "User Not Found" });
        }

        const group: GroupDocument[] | null = await Group.find({
            _id: req.params.groupId,
        });

        // const groups: GroupDocument[] | null = await Group.find({
        //     _id: { $in: user.groups },
        // });

        res.status(200).json(group);
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
    }
};
