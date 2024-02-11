import AsyncStorage from "@react-native-async-storage/async-storage";
import { jwtDecode } from "jwt-decode";
import jwt from "jsonwebtoken";

interface User {
  _id: string;
  email: string;
  userName: string;
}

export const setToken = async (user: User) => {
  const token = jwt.sign(
    {
      _id: user._id,
      email: user.email,
      userName: user.userName,
    },
    String(process.env.SECRET_KEY),
    {
      expiresIn: "7d",
    }
  );

  try {
    await AsyncStorage.setItem("token", token);
  } catch (error) {
    console.error("Error saving token to AsyncStorage:", error);
  }
};

export const getToken = async () => {
  try {
    return await AsyncStorage.getItem("token");
  } catch (error) {
    console.error("Error getting token from AsyncStorage:", error);
    return null;
  }
};

export const decodeToken = async (token: string) => {
  try {
    return jwtDecode<User>(token);
  } catch (error) {
    console.error("Error decoding token:", error);
    return null;
  }
};

export const removeToken = async () => {
  try {
    await AsyncStorage.removeItem("token");
  } catch (error) {
    console.error("Error removing token from AsyncStorage:", error);
  }
};
