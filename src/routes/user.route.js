import { Router } from "express";
import { userLogin, userLogout, userRegister } from "../controllers/user.controller.js";
import passport from "passport";
const router = Router();

router.route("/register").post(userRegister);
router.route("/login").post(userLogin);

// // refresh token rotation
// router.route("/refresh").get(refreshTokenRotation)

// // protected route
// router.route("/allUser").get(verifyJwt,isBlock, allUser);
// router.route("/").get(verifyJwt,isBlock, getUser);
// router.route("/deleteAccount").delete(verifyJwt,isBlock, deleteUsers);
// router.route("/blockAccount").put(verifyJwt,isBlock, blockUsers);  //block or unblock
router
  .route("/logout")
  .get(passport.authenticate("jwt", { session: false }), userLogout);

export default router;
