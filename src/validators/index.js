import { body } from "express-validator";

const userRegisterValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()
      .withMessage("Username should be lower case")
      .isLength({ min: 3 })
      .withMessage("Username should be min 3 char long"),
    body("password").trim().notEmpty().withMessage("Pwd is required"),
    body("fullName").optional().trim(),
  ];
};

const userLoginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("Email is invalid"),
    body("password").notEmpty().withMessage("Password is required"),
  ];
};

const userChangeCurrentPwdValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("Old password is required"),
    body("newPassword").notEmpty().withMessage("New password is required"),
  ];
};

const userForgotPwdValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Eamil is invalid"),
  ];
};

const userResetForgotPwdValiator = () => {
  return [body("newPassword").notEmpty().withMessage("Password is required")];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPwdValidator,
  userForgotPwdValidator,
  userResetForgotPwdValiator
};
