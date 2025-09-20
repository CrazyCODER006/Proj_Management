import { User } from "../models/user.models.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";
import jwt from "jsonwebtoken"

const generateAccessandRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating access token",
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  const existingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existingUser) {
    throw new ApiError(409, "User with email or username already exists", []);
  }

  const user = await User.create({
    email,
    password,
    username,
    isEmailVerified: false,
  });

  const { unHashedToken, HashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = HashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -emailVerificationToken -refreshToken -emailVerificationExpiry",
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering a user");
  }

  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        "User registered and verification mail sent on email",
      ),
    );
});

const login = asyncHandler(async (req, res) => {
  const { email, password, username } = req.body;

  if (!username || !email) {
    throw new ApiError(400, "Username or email is required");
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(400, "User doesn't exist");
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(400, "pwd not valid");
  }

  const { accessToken, refreshToken } = await generateAccessandRefreshTokens(
    user._id,
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully",
      ),
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: "",
      },
    },
    {
      new: true,
    },
  );
  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const getCurrentUser = asyncHandler (async (req, res) => {
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        req.user,
        "Current user fetched successfully"
      )
    )
})

const verifyEmail = asyncHandler (async (req, res) => {
  const {verificationToken} =  req.params
  
  if(!verificationToken){
    throw new ApiError(400, "Email verification token missing")
  }

  let HashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex")

    const user = await User.findOne({
      emailVerificationToken: HashedToken,
      emailVerificationExpiry: {$gt: Date.now()}
    })

    if(!user){
      throw new ApiError(400, "Token invalid or expired");
    }

    user.emailVerificationToken = undefined;
    user.emailVerificationExpiry = undefined;

    user.isEmailVerified = true
    await user.save({validateBeforeSave: false});

    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          {
            isEmailVerified: true
          },
          "Email is verified"
        )
      )

})

const resendEmailVerification = asyncHandler (async (req, res) => {
  const user = await user.findById(req.user?._id);

  if(!user){
    throw new ApiError(404, "User doesn't exists")
  }

  if(user.isEmailVerified){
    throw new ApiError(409, "Email already verified")
  }

  const { unHashedToken, HashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = HashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "Mail has been sent to your email"
      )
    )
})

const refreshAccessToken = asyncHandler (async (req, res) => {
  const incomingRefreshoken = req.cookies.refreshToken || req.body.refreshToken

  if(!incomingRefreshoken){
    throw new ApiError(401, "Unauthorized access")
  }

  try  {
    const decodedToken = jwt.verify(incomingRefreshoken, process.env.REFRESH_TOKEN_SECRET)

    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(401, "Invaid refresh Token");
    }

    if(incomingRefreshoken !== user?.refreshToken){
      throw new ApiError(401, "refresh token is expired");
    }

    const options = {
      httpOnly: true,
      secure: true
    }

    const {accessToken, refreshToken: newRefreshToken} = await generateAccessandRefreshTokens(user._id)

    user.refreshToken = newRefreshToken;
    await user.save()

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(200, { accessToken, refreshToken: newRefreshToken },
          "access Token refreshed"
        ),
      );
  } catch (error) {
      throw new ApiError(401, "invalid refresh token");
  }
})

const forgotPasswordReq = asyncHandler (async (req, res) => {
  const {email} = req.body

  const user = await User.findOne({email})

  if(!user){
    throw new ApiError(404, "User doesn't exxist",[])
  }

  const {unHashedToken, HashedToken, tokenExpiry} = user.generateTemporaryToken();

  user.forgotPasswordToken = HashedToken
  user.forgotPasswordExpiry = tokenExpiry

  await user.save({validateBeforeSave: false})

  await sendEmail({
    email: user?.email,
    subject: "Password reset request",
    mailgenContent: forgotPasswordMailgenContent(
      user.username,
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "password reset mail has been sent to mail Id"
      )
    )
})

const resetForgotPwd = asyncHandler (async (req, res) => {
  const {resetToken} = req.params
  const {newPassword} = req.body

  let HashedToken = crypto
    .createHash("sha256")
    .update(resetToken0)
    .digest("hex")

    const user = await User.findOne({
      forgotPasswordToken: HashedToken,
      forgotPasswordExpiry: {$gt: Date.now()}
    })

    if(!user){
      throw new ApiError(489, "Token is invalid or expired")
    }

    user.forgotPasswordExpiry = undefined
    user.forgotPasswordToken = undefined

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
      .status(200)
      .json(
        new ApiResponse(
          200,
          {},
          "Password reset Successfully"
        )
      )
})

const changeCurrentPassword = asyncHandler (async (req, res) => {
  const {oldPassword, newPassword} = req.body

  const user = await User.findById(req.user?._id)

  const isPasswordValid = await user.isPasswordCorrect(oldPassword)

  if(!isPasswordValid){
    throw new ApiError(400, "Invalid old password")
  }

  user.password = newPassword
  await user.save({validateBeforeSave: false})

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        {},
        "Password changed successfully"
      )
    )
})

export {
  registerUser,
  login,
  logoutUser,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
  forgotPasswordReq,
  resetForgotPwd,
  changeCurrentPassword,
};