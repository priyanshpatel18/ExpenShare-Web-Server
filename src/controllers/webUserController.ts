import bcrypt from "bcrypt";
import { UploadApiResponse } from "cloudinary";
import ejs from "ejs";
import { Request, Response } from "express";
import otpGenerator from "otp-generator";
import path from "path";
import OTP, { OTPDocument } from "../models/otpModel";
import User, { UserDocument } from "../models/userModel";
import { getToken, setToken, setUserData } from "../service/auth";
import cloudinary from "../utils/cloudinary";
import transporter from "../utils/sendMailUtils";

// POST : /user/register
export const registerUser = async (req: Request, res: Response) => {
  try {
    const { userData } = req.cookies;

    const user = getToken(userData);

    if (!user || typeof user === "string") {
      // Additional type checking
      return res.status(401).json({ message: "Internal Server Error" });
    }

    const { email, userName, profilePicture } = user;

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

    // Create User if
    User.create({
      email: email as string,
      userName: userName as string,
      profilePicture: profileUrl,
      publicId,
      password: user.password as string,
    });

    const token = setToken({
      email: email as string,
      userName: userName as string,
    });
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
    res.clearCookie("userData");
    res.clearCookie("email");
    res.status(200).send("User registered successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
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
      return res.status(401).send("You need to Register First");
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

// POST: /user/sendVerificationMail
export const sendVerificationMail = async (req: Request, res: Response) => {
  const { email, userName, password } = req.body;
  const profilePicture = req.file?.path;

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

  try {
    await transporter.sendMail(mailOptions);

    // Hash OTP and save it in the database
    const salt = await bcrypt.genSalt(10);
    const hashedOtp = await bcrypt.hash(otp, salt);

    const otpDocument: OTPDocument = await OTP.create({
      otp: hashedOtp,
      email: email,
    });

    // Set the Registration Data in Token
    const userData = setUserData({
      email,
      userName,
      password,
      profilePicture,
    });
    res.cookie("userData", userData, {
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
    res.status(500).send("Internal Server Error");
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

    return res.status(200);
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal server error");
  }
};

// GET: /user/getUser
export const getUser = async (req: Request, res: Response) => {
  const user: UserDocument = req.user;

  try {
    return res.status(200).json(user);
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal server error");
  }
};

// POST : /user/sendMail
export const sendMail = async (req: Request, res: Response) => {
  const { email } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(400).send("Email doesn't exist");
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

  try {
    await transporter.sendMail(mailOptions);

    // Hash OTP and save it in the database
    const salt = await bcrypt.genSalt(10);
    const hashedOtp = await bcrypt.hash(otp, salt);

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
    res.status(500).send("Internal Server Error");
  }
};

// POST : /user/resetPassword
export const resetPassword = async (req: Request, res: Response) => {
  const { password } = req.body;
  const { email } = req.cookies;

  if (!email) {
    return res.status(400).send("Internal Server Error");
  }

  try {
    const user: UserDocument | null = await User.findOne({ email });

    if (!user) {
      return res.status(400).send("User not Found");
    }

    user.password = password;
    user.save();
    res.clearCookie("email");
    res.status(200).send("User registered successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
};
