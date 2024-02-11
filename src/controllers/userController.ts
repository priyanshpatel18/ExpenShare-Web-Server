import bcrypt from "bcrypt";
import { UploadApiResponse } from "cloudinary";
import ejs from "ejs";
import { Request, Response } from "express";
import nodemailer from "nodemailer";
import SMTPTransport from "nodemailer/lib/smtp-transport";
import otpGenerator from "otp-generator";
import path from "path";
import User, { UserDocument } from "../models/userModel";
import { setToken } from "../service/auth";
import cloudinary from "../utils/cloudinary";
import { deleteSession } from "../utils/sessionUtils";

export const registerUser = async (req: Request, res: Response) => {
  try {
    const { email, userName, password } = req.body;
    const profilePicture = req.file?.path;
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

    const user: UserDocument | null = await User.findOne({
      $or: [{ email: email }, { userName: userName }],
    });
    // Check for unique Email
    if (user?.email === email) {
      return res.status(400).send("Email should be unique");
    }
    // Check for unique userName
    if (user?.userName === userName) {
      return res.status(400).send("Username should be unique");
    }

    // Create User if passed all checks
    User.create({
      email,
      userName,
      profilePicture: profileUrl,
      publicId,
      password,
    });

    deleteSession(req, res);
    res.clearCookie("connect.sid");
    res.status(200).send("User registered successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
};

export const loginUser = async (req: Request, res: Response) => {
  const { userNameOrEmail, password } = req.body;

  console.log(userNameOrEmail, password);

  try {
    const user: UserDocument | null = await User.findOne({
      $or: [{ email: userNameOrEmail }, { userName: userNameOrEmail }],
    });

    // Check if User Exist or not
    if (!user) {
      return res.status(401).send("You need to Register First");
    }
    // Check if User has Google Account or Not
    if (!user.password) {
      return res.status(402).send("You need to login via Google");
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
      // Set Token in Cookies if password is correct
      const token = setToken(user);

      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
      });
      res.status(201).send("Login Successfully");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
};

export const sendMail = async (req: Request, res: Response) => {
  const { email } = req.body;

  const user: UserDocument | null = await User.findOne({ email });
  // Check for User Existence
  if (!user) {
    return res.status(401).send("You need to Register First");
  }
  // Set Email in the session
  req.session.email = email;

  // Generate OTP and set it in the session
  const otp: string = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  req.session.otp = otp;

  // Configure Transporter
  const transporter: nodemailer.Transporter<SMTPTransport.SentMessageInfo> =
    nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
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

  // Send Mail Via Transporter
  try {
    await transporter.sendMail(mailOptions);
    res.status(200).send("OTP sent successfully");
  } catch (error) {
    deleteSession(req, res);
    res.clearCookie("connect.sid");
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};

export const verifyOtp = (req: Request, res: Response) => {
  const { inputOtp } = req.body;
  const { otp, email } = req.session;

  // Verify OTP
  try {
    if (inputOtp !== otp) {
      res.status(401).send("Incorrect OTP");
      return;
    }

    res.status(200).json({ email: email });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal server error");
  }
};

export const getEmail = (req: Request, res: Response) => {
  // Get Email from Session and send json
  const { email } = req.session;

  try {
    if (!req.session || !req.session.email) {
      return res.status(401).send("Session data not found");
    }

    if (!email) {
      return res.send(401).send("Error Fetching Email");
    }

    res.status(200).json({ email });
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal server error");
  }
};

export const sendEmailVerificationMail = async (
  req: Request,
  res: Response
) => {
  const { email } = req.body;

  // Set Email in the session
  req.session.email = email;

  // Generate OTP and set it in the session
  const otp: string = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  req.session.otp = otp;

  // Configure Transporter
  const transporter: nodemailer.Transporter<SMTPTransport.SentMessageInfo> =
    nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
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

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    deleteSession(req, res);
    res.clearCookie("connect.sid");
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
};

export const getUser = async (req: Request, res: Response) => {
  const user: UserDocument = req.user;

  try {
    return res.status(200).json(user);
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal server error");
  }
};
