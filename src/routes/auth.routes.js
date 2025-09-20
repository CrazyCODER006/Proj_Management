import { Router } from "express";
import { changeCurrentPassword, forgotPasswordReq, getCurrentUser, login, logoutUser, refreshAccessToken, registerUser, resendEmailVerification, resetForgotPwd, verifyEmail } from "../controllers/auth.controllers.js"
import { validate } from "../middlewares/validator.middleware.js";
import { userChangeCurrentPwdValidator, userForgotPwdValidator, userLoginValidator, userRegisterValidator, userResetForgotPwdValiator } from "../validators/index.js"
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

//unsecure routes
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/forgot-password").post(userForgotPwdValidator(), validate, forgotPasswordReq);
router.route("/reset-password/:resetToken").post(userResetForgotPwdValiator(), validate, resetForgotPwd);

//secure routes
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/current-user").post(verifyJWT, getCurrentUser);
router.route("/change-password").post(verifyJWT, userChangeCurrentPwdValidator(), validate, changeCurrentPassword);
router.route("/resend-email-verification").post(verifyJWT, resendEmailVerification);

export default router;