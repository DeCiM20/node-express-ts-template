import express, { Request, Response } from "express"
import { signIn, signUp, signOut, refresh, profile, signInRequest } from "./controller"
import { protectedRoute, verifyRefresh } from "~/middleware/auth"

const router = express.Router()

router.post("/sign-up", signUp)

router.post("/sign-in", signIn)

router.post("/request-code", signInRequest)

router.post("/refresh", verifyRefresh, refresh)

router.post("/sign-out", protectedRoute, signOut)

router.get("/profile", protectedRoute, profile)

router.get("/ping", protectedRoute, (_req: Request, res: Response) =>  res.status(200).json({ success: true }))

export default router
