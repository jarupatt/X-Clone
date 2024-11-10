import bcrypt from "bcryptjs";
import { v2 as cloudinary } from "cloudinary";

import Notification from "../models/notification.model.js";
import User from "../models/user.model.js";

export const getUserProfile = async (req, res) => {
  const { userName } = req.params;

  try {
    const user = await User.findOne({ userName }).select("-passWord");
    if (!user) {
      return res.status(404).json({
        error: "User not found!",
      });
    }
    res.status(200).json({ user });
  } catch (error) {
    console.log("Error in getUserProfile", error.message);
    res.status(500).json({
      error: error.message,
    });
  }
};

export const followUnfollowUser = async (req, res) => {
  try {
    const { id } = req.params;
    const userToModify = await User.findById(id);
    const currentUser = await User.findById(req.user._id);

    if (id === req.user._id.toString()) {
      return res.status(400).json({
        error: "You can't follow/unfollow yourself",
      });
    }

    if (!userToModify || !currentUser) {
      return res.status(400).json({
        error: "User not found.",
      });
    }

    const isFollowing = currentUser.following.includes(id);

    if (isFollowing) {
      // Unfollow the user
      await User.findByIdAndUpdate(id, { $pull: { followers: req.user._id } });
      await User.findByIdAndUpdate(req.user._id, { $pull: { following: id } });
      // TODO return the id of the user as a response
      res.status(200).json({
        message: "User unfollowed successfully",
      });
    } else {
      // Follow the user
      await User.findByIdAndUpdate(id, { $push: { followers: req.user._id } });
      await User.findByIdAndUpdate(req.user._id, { $push: { following: id } });
      // Send notifications to the user
      const newNotification = new Notification({
        type: "follow",
        from: req.user._id,
        to: userToModify._id,
      });

      await newNotification.save();

      // TODO return the id of the user as a response
      res.status(200).json({
        message: "User followed successfully",
      });
    }
  } catch (error) {
    console.log("Error in followUnfollowUser", error.message);
    res.status(500).json({
      error: error.message,
    });
  }
};

export const getSuggestedUsers = async (req, res) => {
  try {
    const userId = req.user._id;
    const usersFollowByMe = await User.findById(userId).select("following");
    const users = await User.aggregate([
      {
        $match: {
          _id: { $ne: userId }, // ne = not equal
        },
      },
      { $sample: { size: 10 } },
    ]);
    const filterdUsers = users.filter(
      (user) => !usersFollowByMe.following.includes(user._id)
    );
    const suggestedUsers = filterdUsers.slice(0, 4);

    suggestedUsers.forEach((user) => {
      user.passWord = null;
    });

    res.status(200).json(suggestedUsers);
  } catch (error) {
    console.log("Error in getSuggestedUsers: ", error.message);
    res.status(500).json({
      error: error.message,
    });
  }
};

export const updateUser = async (req, res) => {
  const {
    fullName,
    email,
    passWord,
    userName,
    currentPassWord,
    newPassWord,
    bio,
    link,
  } = req.body;

  let { profileImg, coverImg } = req.body;

  const userId = req.user._id;

  try {
    let user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        error: "User not found",
      });
    }
    if (
      (!newPassWord && currentPassWord) ||
      (newPassWord && !currentPassWord)
    ) {
      return res.status(404).json({
        error: "Please provide both current password and new password",
      });
    }
    if (currentPassWord && newPassWord) {
      const isMatch = await bcrypt.compare(currentPassWord, user.passWord);
      if (!isMatch) {
        return res.status(400).json({
          error: "Current password is incorrect",
        });
      }
      if (newPassWord.length < 6) {
        return res.status(400).json({
          error: "Password must be at least 6 characters long",
        });
      }
      const salt = await bcrypt.genSalt(10);
      user.passWord = await bcrypt.hash(newPassWord, salt);
    }

    if (profileImg) {
      if (user.profileImg) {
        await cloudinary.uploader.destroy(
          user.profileImg.split("/").pop().split(".")[0]
        );
      }
      const uploadedResponse = await cloudinary.uploader.upload(profileImg);
      profileImg = uploadedResponse.secure_url;
    }

    if (coverImg) {
      if (user.coverImg) {
        await cloudinary.uploader.destroy(
          user.coverImg.split("/").pop().split(".")[0]
        );
      }
      const uploadedResponse = await cloudinary.uploader.upload(coverImg);
      coverImg = uploadedResponse.secure_url;
    }

    user.fullName = fullName || user.fullName;
    user.email = email || user.email;
    user.userName = userName || user.userName;
    user.bio = bio || user.bio;
    user.link = link || user.link;
    user.profileImg = profileImg || user.profileImg;
    user.coverImg = coverImg || user.coverImg;

    user = await user.save();

    user.passWord = null;

    return res.status(200).json(user);
  } catch (error) {
    console.log("Error in updateUser", error.message);
    return res.status(400).json({
      error: error.message,
    });
  }
};
