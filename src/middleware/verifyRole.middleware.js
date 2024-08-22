import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const verifyRole = (role = "USER") => {
  return (req, res, next) => {
    const user = req?.user;

    if (user?.block) {
      throw new ApiError(401, "User is Blocked");
    }
 
    if (user?.role !== role) {
      throw new ApiError(403, "Forbidden: Insufficient permissions");
    }

    next();
  };
};

export { verifyRole };
