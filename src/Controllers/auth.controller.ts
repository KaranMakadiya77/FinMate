import jwt from "jsonwebtoken";
import { asyncHandler } from "../Utils/asyncHandler";
import { ApiError } from "../Utils/apiError";
import { User } from "../Models/user.model";
import { ApiResponse } from "../Utils/apiResponse";
import { IUserDocument } from "../Types/user.types";
import { cookieOption } from "../constants";
import { Token } from "../Types/common.types";

// register
const registerUser = asyncHandler(async (req, res) => {
    // check if email already exists in the db
    const existingUser = await User.findOne({ email: req.body.email });

    // throw error
    if (existingUser) {
        throw new ApiError(400, "User already exists");
    }

    // create user
    const user = await User.create(req.body);

    // GET THE CREATED USER WITHOUT THE PASSWORD AND REFERESH FIELDS AND THROW ERROR IF USER DOES NOT EXISTS
    const createduser = await User.findById(user._id).select("-password -refreshToken -otp -otp_expiry -__v");

    // throw error if user is not created
    if (!createduser) throw new ApiError(500, "Internal server error");

    // return response
    return res.status(201).json(new ApiResponse(201, createduser, "User created successfully"));
});

// login
const loginUser = asyncHandler(async (req, res) => {
    // check for user
    const user: IUserDocument | null = await User.findOne({
        email: req.body.email,
    });

    // throw error if user deos not exists
    if (!user) throw new ApiError(404, "User not found", [`Email ${req.body.email} not found`]);

    // check wheather the password is valid or not
    const isPasswordCorrect = await user.isPasswordCorrect(req.body.password);

    // throw error is password is invalid
    if (!isPasswordCorrect) throw new ApiError(401, "Invalid Password !!!", ["Invalid password"]);

    // generate tokens
    const { accessToken, refreshToken } = await user.generateAccessAndRefreshTokens();

    // fetch logged in user
    const loggedinUser = await User.findById(user._id).select("-password -refreshToken -otp -otp_expiry -__v");

    // return response
    return res
        .status(200)
        .cookie("accessToken", accessToken, cookieOption)
        .cookie("refreshToken", refreshToken, cookieOption)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedinUser,
                    accessToken,
                    refreshToken,
                },
                "User logged in successfully"
            )
        );
});

// refresh accesstoken
const refreshAccessToken = asyncHandler(async (req, res) => {
    // GET THE TOKEN FROM COOKIES OR REQUEST BODY
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    //  THROW ERROR IF THERE ARE NO TOKENS
    if (!incomingRefreshToken) throw new ApiError(401, "Unauthorized Request");

    //  VERIFY THE TOKEN
    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET ?? "") as Token;

    // GET THE USER FROM THE DATABASE
    const user: IUserDocument | null = await User.findById(decodedToken._id);

    //  THROW ERROR UF THERE ARE NO USER ASSOCIATED WITH THE GIVEN REFERESH TOKEN
    if (!user) throw new ApiError(401, "Invalid Referesh token");

    // GENERATE NEW ACCESSTOKEN AND REFRESHTOKEN
    const { accessToken, refreshToken } = await user.generateAccessAndRefreshTokens();

    // Return Response
    return res
        .status(200)
        .cookie("accessToken", accessToken, cookieOption)
        .cookie("refreshToken", refreshToken, cookieOption)
        .json(new ApiResponse(200, { accessToken, refreshToken }, "Token refereshed generated sucessfully"));
});

// change password
const changePassword = asyncHandler(async (req, res) => {
    // GET THE OLD AND NEW PASSWORD FROM THE REQUEST BODY
    const { oldPassword, newPassword } = req.body;

    // FIND THE USER BY THE USER ID
    const user: IUserDocument | null = await User.findById(req.user?._id);

    // throw error
    if (!user) throw new ApiError(404, "User not found");

    // CHECK WEATHER THE OLD PASSWORD IS VALID OR NOT
    const isPasswordValid = await user.isPasswordCorrect(oldPassword);

    // IF OLD PASSWORD IS NOT VALID THEN THROW NEW ERROR
    if (!isPasswordValid) throw new ApiError(400, "Invalid password", ["Old password is invalid"]);

    //  IF THE PASSWORD IS VALID THEN UPDATE IT IN THE DATABASE
    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    // RETURN THE RESPONSE
    return res.status(200).json(new ApiResponse(200, {}, "Password Changed sucessfully"));
});

// logout
const logoutUser = asyncHandler(async (req, res) => {
    // Find the user by ID and remove refresh Token
    const updatedUser = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $unset: {
                refreshToken: 1,
            },
        },
        {
            new: true,
        }
    );

    // Throw Error if User is not created
    if (!updatedUser) throw new ApiError(500, "Inter server error !!!");

    // return response
    return res
        .status(200)
        .clearCookie("accessToken", cookieOption)
        .clearCookie("refreshToken", cookieOption)
        .json(new ApiResponse(200, {}, "Logged out sucessfully"));
});

export { registerUser, loginUser, refreshAccessToken, changePassword, logoutUser };
