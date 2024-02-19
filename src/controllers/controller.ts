import bcrypt from "bcrypt";
import { UploadApiResponse, v2 as cloudinary } from "cloudinary";
import ejs from "ejs";
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
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
} from "../models/models";

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
      userDataId,
    });

    if (!userData) {
      return res.status(401).json({ message: "User Data Expired" });
    }

    // Destructure the Decoded User
    const { email, userName, password, profilePicture } = userData!;

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
      httpOnly: true,
      secure: true,
      sameSite: "none",
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
  const { userNameOrEmail, password } = req.body;

  try {
    const user: UserDocument | null = await User.findOne({
      $or: [{ email: userNameOrEmail }, { userName: userNameOrEmail }],
    });

    // Check if User Exist or not
    if (!user) {
      return res.status(401).json({ message: "You need to Register First" });
    }

    // Comapre the Password using bcrypt
    const passwordMatch: boolean = await bcrypt.compare(
      password,
      user.password
    );
    if (!passwordMatch) {
      res.status(501).send("Incorrect Password");
      return;
    } else {
      // Set Token in Cookies if Password is correct
      const token: string = setToken(user);
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
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
    const UserDataDocument: UserDataDocument = await UserData.create(userData);

    // Set the User Data Id in the Cookies
    res.cookie("userDataId", UserDataDocument._id, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
    // Set the OTP ID in the cookies
    res.cookie("otpId", otpDocument._id, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
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
      httpOnly: true,
      secure: true,
      sameSite: "none",
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
      httpOnly: true,
      secure: true,
      sameSite: "none",
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
  const { email } = req.cookies;

  if (!email) {
    return res.status(400).json({ message: "Internal Server Error" });
  }

  try {
    const user: UserDocument | null = await User.findOne({ email });

    if (!user) {
      return res.status(400).send("User not Found");
    }

    user.password = password;
    user.save();
    res.clearCookie("email");
    res.status(200).json({ message: "User registered successfully" });
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
    return res.status(500).send("Internal server error");
  }
};

// POST: /transaction/add
export const addTransaction = async (req: Request, res: Response) => {
  const { incomeFlag, amount, category, title, notes, transactionDate } =
    req.body;
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
      transactionAmount: String(amount),
      category: String(category),
      transactionTitle: String(title),
      notes: String(notes),
      invoiceUrl,
      publicId,
      transactionDate: String(transactionDate),
      type: incomeFlag,
      createdBy: new Types.ObjectId(user._id),
    };

    const transactionDocument: TransactionDocument = await Transaction.create(
      transactionObject
    );

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
            income: incomeFlag === "income" ? Number(amount) : 0,
            expense: incomeFlag === "expense" ? Number(amount) : 0,
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

    if (incomeFlag === "income") {
      user.incomes.push(transactionId);
      user.totalBalance += Number(amount);
      user.totalIncome += Number(amount);
      // Add to History
    } else if (incomeFlag === "expense") {
      user.expenses.push(transactionId);
      user.totalBalance -= Number(amount);
      user.totalExpense += Number(amount);
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

    const transactions: TransactionDocument[] | null = await Transaction.find({
      createdBy: user._id,
    });

    return res.status(200).json({ transactions });
  } catch (error) {
    return res.status(500).json({ message: "Internal Server Error" });
  }
};
