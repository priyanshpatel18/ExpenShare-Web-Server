import jwt from "jsonwebtoken";

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

export const setToken = (user: User) => {
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
