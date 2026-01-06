import User from '../models/User.js';
import { generateAccessToken, generateEmailVerificationToken, generateRefreshToken, generateResetToken } from '../utils/generateToken.js';
import jwt from 'jsonwebtoken';
import sgMail from '@sendgrid/mail';
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Get all Users List
export const userLists = async (req, res) => {
  const users = await User.find();
  res.json(users);
};

// Get Single user details
export const userDetails = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error fetching user", error: error.message });
  }
};

// Post create User (register)
export const createUser = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ message: "Conflict: Email already exists!" });
    }
    const newUser = new User({ ...req.body, email });
    const savedUser = await newUser.save();

    // Generate a random 4-digit code for email verification
    const emailVerificationToken = Math.floor(1000 + Math.random() * 9000).toString();
    savedUser.emailVerificationToken = emailVerificationToken;
    savedUser.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await savedUser.save();

    // Send the code to the user's email
    const msg = {
      to: savedUser.email,
      from: process.env.EMAIL_FROM || 'support@sujjalkhadka.com.np',
      subject: 'Your Electomart Email Verification Code',
      text: `Your verification code is: ${emailVerificationToken}`,
      html: `<p>Your Electomart verification code is: <b>${emailVerificationToken}</b></p>`,
    };
    await sgMail.send(msg);

    res.status(201).json({
      message: 'User created successfully. Please verify your email with the code sent to your email address.',
      user: {
        id: savedUser._id,
        name: savedUser.name,
        email: savedUser.email,
        role: savedUser.role,
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Error creating User", error: error.message });
  }
};

// Update user
export const updateUser = async (req, res) => {
  try {
    let updateData = { ...req.body };
    const user = await User.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ message: "Error updating User" });
  }
};

// Delete user
export const deleteUser = async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: "User deleted successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting User" });
  }
};

// Login user
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({ 
        message: "Email not verified. Please verify your email first.",
        isEmailVerified: false 
      });
    }

    // Allow login even if not verified (Commented out old logic description or just proceed)
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      message: "Login successful",
      token: accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Login failed", error: error.message });
  }
};

// Logout user
export const logoutUser = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
      const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
      const user = await User.findById(decoded.id);
      if (user) {
        user.refreshTokens = user.refreshTokens.filter(token => token !== refreshToken);
        await user.save();
      }
    }
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.status(200).json({ message: "User logged out successfully" });
  } catch (error) {
    res.status(500).json({ message: "Logout failed", error: error.message });
  }
};

// Username Change
export const changeUserName = async (req, res) => {
  try {
    const { userId } = req.params;
    const { newName } = req.body; // <-- use newName

    const user = await User.findByIdAndUpdate(userId, { name: newName }, { new: true }); // <-- update name
    if (!user) return res.status(404).json({ message: "User not found" });

    res.status(200).json({ message: "Name updated successfully", user });
  } catch (error) {
    res.status(500).json({ message: "Error updating name", error: error.message });
  }
};

// Reset password
export const resetPassword = async (req, res, next) => {
  try {
    const { token } = req.params;
    const { password } = req.body;
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    next(error);
  }
};

// Request password reset
export const requestPasswordReset = async (req, res, next) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const resetToken = generateResetToken();
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
    const msg = {
      to: user.email,
      from: process.env.EMAIL_FROM || 'support@sujjalkhadka.com.np',
      subject: 'Password Reset Request',
      text: `Reset your password: ${resetUrl}`,
      html: `<p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`,
    };
    await sgMail.send(msg);

    res.status(200).json({ message: "Password reset link sent to email" });
  } catch (error) {
    next(error);
  }
};

// Email verification by code (for UI: POST /users/verify-code { email, code })
export const verifyEmailCode = async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: "User not found" });
    if (
      user.emailVerificationToken === code &&
      user.emailVerificationExpires > Date.now()
    ) {
      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();

      // Generate tokens and set cookies for automatic login
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });
      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      user.refreshTokens = user.refreshTokens || [];
      user.refreshTokens.push(refreshToken);
      await user.save();

      return res.status(200).json({
        message: "Email verified and user logged in successfully!",
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified
        }
      });
    } else {
      return res.status(400).json({ message: "Invalid or expired verification code." });
    }
  } catch (error) {
    res.status(500).json({ message: "Verification failed", error: error.message });
  }
};

// Resend verification code to user's email (for UI: POST /users/resend-code { email })
export const resendVerificationCode = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: "User not found" });
    if (user.isEmailVerified) return res.status(400).json({ message: "Email is already verified." });

    // Generate a new 4-digit code
    const emailVerificationToken = Math.floor(1000 + Math.random() * 9000).toString();
    user.emailVerificationToken = emailVerificationToken;
    user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await user.save();

    // Send the code to the user's email
    const msg = {
      to: user.email,
      from: 'support@sujjalkhadka.com.np',
      subject: 'Your Electomart Email Verification Code',
      text: `Your verification code is: ${emailVerificationToken}`,
      html: `<p>Your Electomart verification code is: <b>${emailVerificationToken}</b></p>`,
    };
    await sgMail.send(msg);

    res.status(200).json({ message: "Verification code resent. Please check your email." });
  } catch (error) {
    res.status(500).json({ message: "Failed to resend verification code", error: error.message });
  }
};

// Change password (for profile page)
export const changePassword = async (req, res) => {
  try {
    const userId = req.user.id || req.user._id;
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(userId).select('+password');
    if (!user) return res.status(404).json({ message: "User not found" });
    if (!(await user.comparePassword(oldPassword))) {
      return res.status(400).json({ message: "Current password is incorrect." });
    }
    user.password = newPassword;
    await user.save();
    res.status(200).json({ message: "Password changed successfully." });
  } catch (error) {
    res.status(500).json({ message: "Failed to change password", error: error.message });
  }
};

// Admin approval, role update, and other admin functions remain unchanged
export const updateUserRole = async (req, res) => {
  try {
    const { role } = req.body;
    if (!role || !['admin', 'customer'].includes(role)) {
      return res.status(400).json({ message: "Invalid role" });
    }
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "Role updated", user });
  } catch (error) {
    res.status(500).json({ message: "Error updating role", error: error.message });
  }
};