import { userShopper } from "../../models/user/auth/user.model.js";
import bcrypt from "bcryptjs";
import {
  generateVerificationToken,
  generateAccessToken,
} from "../../helpers/auth/token.verification.js";
import { sendOTP } from "../../helpers/auth/nodemailer.js";
import jwt from "jsonwebtoken";
import { userOtp } from "../../models/user/auth/otp.model.js";

const createUser = async (req, res) => {
  try {
    const { fullName, email, password, confirmPassword, dateOfBirth, gender } =
      req.body;

    if (password !== confirmPassword) {
      // return res.status(400).json({
      //   success: false,
      //   message: "Password and Confirm Password does not match",
      // });
      throw new Error("Password and Confirm Password does not match");
    }

    const emailExist = await userShopper.findOne({ email: email });
    if (emailExist) {
      // return res
      //   .status(400)
      //   .json({ success: false, message: "Email already exists" });
      throw new Error("Email already exists");
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await userShopper.create({
      fullName,
      email,
      password: hashedPassword,
      dateOfBirth,
      gender,
    });

    if (newUser) {
      await sendOTP(newUser);

      const token = generateVerificationToken(newUser._id);
      console.log(token);
      res.status(200).json({ success: true, message: `${token}` });
    }
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

const verifyUser = async (req, res) => {
  const { otp } = req.body;
  res.setHeader("Access-Control-Allow-Headers", "Authorization");
  let token = null;
  const authHeader = req.headers["authorization"]?.trim();
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.split(" ")[1];
  } else {
    console.log("Authorization header is missing or in an invalid format.");
  }

  if (!token) {
    // return res.json({
    //   success: false,
    //   message: "Error in Validation, Re-Type OTP",
    // });
    throw new Error("Error in Validation, Re-Type OTP");
  }

  const payload = jwt.verify(token, process.env.jwt_VERIFICATION_PASS);

  try {
    const userOTP = await userOtp.findOne({
      user: payload.id,
      otpType: "verify-email",
    });

    if (!userOTP) {
      // return res.json({
      //   success: false,
      //   message: "User with OTP does not exist",
      // });
      throw new Error("User with OTP does not exist");
    }
    if (userOTP.otp === otp) {
      const User = await userShopper.findByIdAndUpdate(userOTP.user, {
        isEmailVerified: true,
      });
      await userOtp.findByIdAndDelete(userOTP._id);

      //Generating Access Token for verified User
      const payload = {
        id: User._id,
        role: User.role,
        email: User.email,
        fullName: User.fullName,
      };
      // const accessToken = generateAccessToken(payload);
      // console.log(accessToken);

      const accessToken = jwt.sign(payload, process.env.jwt_ACCESS_TOKEN, {
        expiresIn: "60m",
      });

      console.log(accessToken);
      res.cookie("token", accessToken, { httpOnly: true, secure: false }).json({
        success: true,
        message: `Logged In Successfully`,
        user: {
          email: User.email,
          role: User.role,
          id: User._id,
          fullName: User.fullName,
        },
      });
    }
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const User = await userShopper.findOne({ email });
    if (!User) {
      throw new Error(`User does not Exists, Please register first`);
    }

    const isMatches = await bcrypt.compare(password, User.password);
    if (!isMatches) {
      throw new Error(`Password credentials error`);
    }

    if (!User.isEmailVerified) {
      const userOTP = await userOtp.findOne({
        user: User._id,
        otpType: "verify-email",
      });
      console.log(userOTP);
      console.log("--------");
      console.log(userOTP);
      if (Date.now() > userOTP?.expiry) {
        await userOtp.deleteMany({ user: User._id, otpType: "verify-email" });
      }
      if (userOTP?.expiry) {
        console.log(
          `OTP still valid, redirect to OTP Page, with the saved Verification Token`
        );
        // return res
        //   .status(200)
        //   .json({ success: true, message: `OTP is still valid` });

        throw new Error("Not Verified Yet, Enter OTP");
      } else {
        console.log(`OTP expired, resending OTP`);
        await sendOTP(User);
        const token = generateVerificationToken(User._id);
        return res.json({
          success: false,
          message: `OTP Re-sent to ${User.email}`,
          token: `${token}`,
        });
      }
    }
    //generate access token for verified log in user

    const payload = {
      id: User._id,
      role: User.role,
      email: User.email,
      fullName: User.fullName,
    };
    const token = jwt.sign(payload, process.env.jwt_ACCESS_TOKEN, {
      expiresIn: "60m",
    });

    res.cookie("token", token, { httpOnly: true, secure: false }).json({
      success: true,
      message: "Logged in successfully ",
      user: {
        email: User.email,
        role: User.role,
        id: User._id,
        fullName: User.fullName,
      },
    });
  } catch (error) {
    res.json({ success: false, message: `${error.message}` });
  }
};

//logout
const logOutUser = (req, res) => {
  res
    .clearCookie("token")
    .json({ success: true, message: "Logged out successfully" });
};

//AuthMiddleWare
const authMiddlWare = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Unauthorised user!" });
  }

  try {
    const decoded = jwt.verify(token, process.env.jwt_ACCESS_TOKEN);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Unauthorized user!",
    });
  }
};

export { createUser, verifyUser, loginUser, logOutUser, authMiddlWare };
