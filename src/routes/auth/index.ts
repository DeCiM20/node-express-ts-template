import express from "express"
import { signIn, signUp, signOut, refresh, profile } from "./controller"
import { protectedRoute, verifyRefresh } from "~/middleware/auth"
import passport from "passport"

const router = express.Router()

router.get("/google", (req, res, next) => {
  passport.authenticate("google", {
    scope: ["email", "profile"],
  })(req, res, next)
})

router.get("/github", (req, res, next) => {
  passport.authenticate("github", {
    scope: ["email", "profile"],
  })(req, res, next)
})

router.get("/google/callback", passport.authenticate("google"))

router.get("/github/callback", passport.authenticate("github"))

router.post("/sign-up", signUp)

router.post("/sign-in", signIn)

router.post("/refresh", verifyRefresh, refresh)

router.post("/sign-out", protectedRoute, signOut)

router.get("/profile", protectedRoute, profile)

router.get("/ping", protectedRoute, (req, res) => {
  return res.status(200).json({ success: true })
})

export default router
