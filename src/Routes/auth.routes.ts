import { Router } from "express";
import { verifyJWT } from "../Middlewares/auth.middleware";
import validate from "../Middlewares/validation.middleware";

import {
    registerUser,
    loginUser,
    refreshAccessToken,
    changePassword,
    logoutUser,
} from "../Controllers/auth.controller";

import {
    userValidationSchema,
    userLoginValidationSchema,
    changepasswordValidationSchema,
} from "../Validations/user.validator";

// create router instance
const router = Router();

// register
router.route("/register").post(validate(userValidationSchema), registerUser);

// login
router.route("/login").post(validate(userLoginValidationSchema), loginUser);

// refresh accesstoken
router.route("/refresh-token").post(refreshAccessToken);

// SECURED ROUTES
router.use(verifyJWT);

// change password
router.route("/changepassword").patch(validate(changepasswordValidationSchema), changePassword);

// logout
router.route("/logout").post(logoutUser);

export default router;
