import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import prisma from "../config/db.config.js";

const generateAccessAndRefereshTokens = async (user) => {
  try {
    const accessToken = jwt.sign(
      {
        id: user?.id,
        email: user?.email,
        name: user?.name,
        role: user?.role,
      },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
      }
    );

    const refreshToken = jwt.sign(
      {
        id: user?.id,
      },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
      }
    );

    const saveUser = await prisma.user.update({
      where: {
        id: user?.id,
      },
      data: {
        refreshToken,
      },
    });

    if (!saveUser) {
      throw new ApiError(500, "Failed to store refresh token");
    }
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating referesh and access token"
    );
  }
};

const userRegister = asyncHandler(async (req, res) => {
  // check all field are given or not
  const { name, email, password } = req.body; // multer separate data as req.body and req.file

  if (!name || !email || !password) {
    throw new ApiError(400, "All fields required");
  }

  // user exist or not
  const existedUser = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (existedUser) {
    throw new ApiError(409, "User already Exist");
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  //create and save to database
  const user = await prisma.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
    },
  });

  if (!user) {
    throw new ApiError(500, "Failed to create user account");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, {}, "User registered Successfully"));
});

const userLogin = asyncHandler(async (req, res) => {
  // check all field are given or not
  const { email, password } = req.body;

  if (!email || !password) {
    throw new ApiError(400, "All fields required");
  }

  //check user with the email exist or not
  const user = await prisma.user.findUnique({
    where: {
      email,
    },
  });

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  if (user?.block) {
    throw new ApiError(303, "Your account is blocked!");
  }

  //check if he password is valid
  const isPasswordValid = await bcrypt.compare(password, user?.password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid Password");
  }

  // save refresh token to db and return access and refresh token
  const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(
    user
  );

  // option for cookie
  const options = {
    httpOnly: true,
    secure: process.env.DEV_MODE !== "development",
    sameSite: "None", // None for cross-site requests
    maxAge: 24 * 60 * 60 * 1000, // only in milisecond format
  };

  return res
    .status(200)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: {
            id: user?.id,
            name: user?.name,
            email: user?.email,
            role: user?.role,
          },
          accessToken,
        },
        "User logged In Successfully"
      )
    );
});

const userLogout = asyncHandler(async (req, res) => {
  console.log(req.user);
  const saveUser = await prisma.user.update({
    where: {
      id: req?.user?.id,
    },
    data: {
      refreshToken: null,
    },
  });

  if (!saveUser) {
    throw new ApiError(500, "Failed to logout");
  }

  const options = {
    httpOnly: true,
    secure: process.env.DEV_MODE !== "development",
    sameSite: "None", // None for cross-site requests
  };

  return res
    .status(200)
    .clearCookie("refreshToken", options) //express method
    .json(new ApiResponse(200, {}, "User logged Out"));
});

// loged in user info
const getUser = asyncHandler(async (req, res) => {

  const user = await prisma.user.findUnique({
    where: { id: req?.user?.id },
    select: {
      id: true,
      name: true,
      email: true,
      role: true,
      createdAt: true,
    },
  });

  if (!user) {
    throw new ApiError(501, "Something went wrong while geting user info");
  }

  res.status(201).json(new ApiResponse(201, { user }, "user Info"));
});

// refresh token rotation and access token generator
const refreshTokenRotation = asyncHandler(async (req, res) => {
  const oldRefreshToken = req.cookies?.refreshToken;

  if (!oldRefreshToken) {
    throw new ApiError(401, "No Refresh Token");
  }

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.DEV_MODE !== "development",
    sameSite: "None", // None for cross-site requests
  });

  //verify the token
  const decodedUser = jwt.verify(
    oldRefreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    (err, userDecoded) => {
      if (err) {
        // console.log("auth error//////////\n", err?.message);
        if (err?.message === "jwt expired") {
          throw new ApiError(401, "Expired RefreshToken token");
        }
        throw new ApiError(401, "Forbidden - Invalid token");
      } else {
        return userDecoded;
      }
    }
  );

  const user = await prisma.user.findUnique({
    where: {
      id: decodedUser.id,
    },
  });
  // console.log(user)
  if (!user) {
    throw new ApiError(401, "User does not exist");
  }
  // console.log(oldRefreshToken !== user?.refreshToken);

  if (oldRefreshToken !== user?.refreshToken) {
    throw new ApiError(401, "Attempt to hack using old refresh token");
  }

  // save refresh token to db and return access and refresh token
  const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(
    user
  );

  const options = {
    httpOnly: true,
    secure: process.env.DEV_MODE !== "development",
    sameSite: "None", // None for cross-site requests
    maxAge: 24 * 60 * 60 * 1000, // only in milisecond format
  };

  return res.status(200).cookie("refreshToken", refreshToken, options).json(
    new ApiResponse(
      200,
      {
        accessToken,
      },
      "Access token created from refresh token"
    )
  );
});

// const allUser = asyncHandler(async (req, res) => {
//   const [users] = await db.query(
//     "SELECT id, name, email, block, updatedAt FROM users"
//   );

//   if (users[0].length === 0) {
//     throw new ApiError(501, "Something went wrong while getting all users");
//   }

//   res.json(new ApiResponse(200, users, "All users"));
// });



// const deleteUsers = asyncHandler(async (req, res) => {
//   const { userIds } = req.body;
//   if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
//     throw new ApiError(400, "Invalid user IDs");
//   }

//   const [result] = await db.query("DELETE FROM users WHERE id IN (?)", [
//     userIds,
//   ]);

//   if (result.affectedRows !== userIds.length) {
//     throw new ApiError(500, "Failed to delete all selected users");
//   }

//   res.status(201).json(new ApiResponse(200, {}, "Users deleted successfully"));
// });

// // need update
// const blockUsers = asyncHandler(async (req, res, next) => {
//   const { userIds, block } = req.body;
//   if (
//     !userIds ||
//     !Array.isArray(userIds) ||
//     userIds.length === 0 ||
//     block === null ||
//     block === undefined
//   ) {
//     throw new ApiError(400, "Invalid user IDs");
//   }

//   const [result] = await db.query(
//     `UPDATE users SET block = ${block} WHERE id IN (?)`,
//     [userIds]
//   );

//   if (result.affectedRows !== userIds.length) {
//     throw new ApiError(
//       500,
//       `Failed to ${block ? "block" : "unblock"}  all selected users`
//     );
//   }

//   res
//     .status(201)
//     .json(
//       new ApiResponse(
//         200,
//         {},
//         `Users ${block ? "blocked" : "unblocked"} successfully`
//       )
//     );
// });

export { userRegister, userLogin, userLogout, refreshTokenRotation, getUser };
