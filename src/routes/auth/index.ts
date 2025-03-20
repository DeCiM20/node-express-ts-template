import express from "express"
import { signIn, signUp, signOut, refresh, profile } from "./controller"
import { protectedRoute, verifyRefresh } from "~/middleware/auth"
const router = express.Router()

router.post("/sign-up", signUp)

router.post("/sign-in", signIn)

router.post("/refresh", verifyRefresh, refresh)

router.post("/sign-out", protectedRoute, signOut)

router.get("/profile", protectedRoute, profile)

router.get("/ping", protectedRoute, (req, res) => {
  return res.status(200).json({ success: true })
})

export default router
