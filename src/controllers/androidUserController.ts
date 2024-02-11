import User, { UserDocument } from "../models/userModel";
import { Request, Response } from "express";
import bcrypt from "bcrypt";
import { setToken } from "../service/androidAuth";

export const loginUser = async (req: Request, res: Response) => {
  const { userNameOrEmail, password } = req.body;
  console.log(userNameOrEmail, password);

  try {
    const user: UserDocument | null = await User.findOne({
      $or: [{ email: userNameOrEmail }, { userName: userNameOrEmail }],
    });

    // Check if User Exist or not
    if (!user) {
      return { error: "User does not exist" };
    }

    const passwordMatch: boolean = await bcrypt.compare(
      password,
      user.password
    );
    if (!passwordMatch) {
      res.status(501).send("Incorrect Password");
      return;
    }
    await setToken(user);
    console.log("Logged In");

    return { user };
  } catch (error) {
    console.error(error);
    return { error: "Internal server error" };
  }
};
