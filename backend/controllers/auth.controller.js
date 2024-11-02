import { generateTokenAndSetCookie } from "../lib/utils/generateToken.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";

export const signup = async (req, res) => {
  try {
    const { fullName, userName, email, passWord } = req.body;

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      return res.status(400).json({
        error: "Invalid email format!",
      });
    }

    const existingUser = await User.findOne({ userName });

    if (existingUser) {
      return res.status(400).json({
        error: "Username is already taken.",
      });
    }

    const existingEmail = await User.findOne({ email });

    if (existingEmail) {
      return res.status(400).json({
        error: "Email is already taken.",
      });
    }

    if (passWord.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters long.",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(passWord, salt);

    const newUser = new User({
      fullName,
      userName,
      email,
      passWord: hashedPassword,
    });

    if (newUser) {
      generateTokenAndSetCookie(newUser._id, res);
      await newUser.save();

      res.status(201).json({
        _id: newUser._id,
        fullName: newUser.fullName,
        userName: newUser.userName,
        email: newUser.email,
        followers: newUser.followers,
        following: newUser.following,
        profileImg: newUser.profileImg,
        coverImg: newUser.coverImg,
      });
    } else {
      res.status(400).json({
        error: "Invalid user data.",
      });
    }
  } catch (error) {
    console.log("Error in signup controller.", error.message);
    res.status(500).json({
      error: "Internal Server Error",
    });
  }
};

export const login = async (req, res) => {
  try {
    const { userName, passWord } = req.body;

    const user = await User.findOne({ userName });
    const isPassWordCorrect = await bcrypt.compare(
      passWord,
      user?.passWord || ""
    );

    if (!user || !isPassWordCorrect) {
      return res.status(400).json({
        error: "Invalid username or password.",
      });
    }

    generateTokenAndSetCookie(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      userName: user.userName,
      email: user.email,
      followers: user.followers,
      following: user.following,
      profileImg: user.profileImg,
      coverImg: user.coverImg,
    });
  } catch (error) {
    console.log("Error in login controller.", error.message);
    res.status(500).json({
      error: "Internal Server Error",
    });
  }
};

export const logout = async (req, res) => {
  try {
    res.cookie("jwt", "", { maxAge: 0 });
    res.status(200).json({
      message: "Logged out successfully",
    });
  } catch (error) {
    console.log("Error in logout controllers", error.message);
    res.status(400).json({
      error: "Internal server error.",
    });
  }
};

export const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-passWord");
    res.status(200).json(user);
  } catch (error) {
    console.log("Error in getMe controller", error.message);
    res.status(500).json({
      error: "Internal Server Error",
    });
  }
};
