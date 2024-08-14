import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import passport from "passport";
import prisma from "./db.config.js";

const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.ACCESS_TOKEN_SECRET,
};

passport.use(
  new JwtStrategy(opts, async function (jwt_payload, done) {
    try {
      console.log("payload: ", jwt_payload);
      const user = await prisma.user.findUnique({
        where: {
          id: jwt_payload.id,
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          block: true,
        },
      });
      console.log("user: ", user);
      if (!user) {
        return done(null, false);
      }
      return done(null, user);
    } catch (error) {
      return done(error, false);
    }
  })
);

export default passport;
