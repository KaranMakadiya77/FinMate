import { Router } from "express";
import { verifyJWT } from "../Middlewares/auth.middleware";
import validate from "../Middlewares/validation.middleware";

import { getUser, updateUser, deleteUser, updateUserBalance } from "../Controllers/user.controller";

import { userUpdateBalanceValidationSchema, userUpdateValidationSchema } from "../Validations/user.validator";

// create router instance
const router = Router();

// SECURED ROUTES
router.use(verifyJWT);

// get user details
router.route("/").get(getUser);

// update user details
router.route("/").put(validate(userUpdateValidationSchema), updateUser);

// update user balance
router.route("/balance").patch(validate(userUpdateBalanceValidationSchema), updateUserBalance);

// delete user
router.route("/").delete(deleteUser);

export default router;
