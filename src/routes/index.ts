import express from "express"
import Auth from "./auth"

const router = express.Router()

router.use("/auth", Auth)

export default router
