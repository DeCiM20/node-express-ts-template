import { Request, Response } from "express"
import { z } from "zod"
import { zBodyParse } from "~/utils/z-parse"
import { v4 } from "uuid"
import { ExpressError } from "~/middleware/error"
import {
  COOKIE_CONFIG,
  createJWT,
  destroySession,
  refreshAccessToken,
} from "~/utils/jwt"

const Users: { id: string; email: string }[] = [] // use db in prod

export const signUp = async (req: Request, res: Response) => {

  const schema = z.object({ email: z.string().email(), password: z.string().max(30) })

  const { success, error, data: input } = zBodyParse(schema, req.body)

  if (!success || error) {
    throw new ExpressError({
      code: "BAD_REQUEST",
      message: "Invalid Inputs!!!",
      error: error,
    })
  }

  if (Users.find(u => u.email === input.email)) {
    throw new ExpressError({
      code: "CONFLICT",
      message: "User already exists!!",
    })
  }

  const id = v4()

  Users.push({ id, email: input.email })

  return res.status(200).json({
    message: "User created successfully!!!",
  })
}

export const signInRequest = async (req: Request, res: Response) => {
  const schema = z.object({ email: z.string().email() })
  const { success, error, data: input } = zBodyParse(schema, req.body)

  if (!success || error) {
    throw new ExpressError({
      code: "BAD_REQUEST",
      message: "Invalid Inputs!!!",
      error: error,
    })
  }

  const user = Users.find(u => u.email === input.email)

  if (!user) {
    throw new ExpressError({
      code: "UNAUTHORIZED",
      message: "Invalid credentials!!",
    })
  }

  return res.status(200).json({success: true, message: "Code sent successfully!"});
}

export const signIn = async (req: Request, res: Response) => {
  const schema = z.object({ email: z.string().email(), code: z.string().max(6).min(6) })
  const { success, error, data: input } = zBodyParse(schema, req.body)

  if (!success || error) {
    throw new ExpressError({
      code: "BAD_REQUEST",
      message: "Invalid Inputs!!!",
      error: error,
    })
  }

  const user = Users.find(u => u.email === input.email)

  if (!user || input.code !== "111111") {
    throw new ExpressError({
      code: "UNAUTHORIZED",
      message: "Invalid credentials!!",
    })
  }

  const uuid = v4()

  const accessToken = await createJWT(user.id, uuid, "access")
  const refreshToken = await createJWT(user.id, uuid, "refresh")

  res.cookie("Access-Token", accessToken, COOKIE_CONFIG.access)
  res.cookie("Refresh-Token", refreshToken, COOKIE_CONFIG.refresh)

  return res.status(200).json({
    id: user.id,
    email: user.email,
  })
}

export const refresh = async (req: Request, res: Response) => {
  const token = req.cookies["Refresh-Token"]

  if (!token) {
    throw new ExpressError({
      code: "BAD_REQUEST",
      message: "Refresh token missing!!",
    })
  }

  const { accessToken, refreshToken } = await refreshAccessToken(token)

  res.cookie("Access-Token", accessToken, {
    ...COOKIE_CONFIG.access,
    maxAge: accessToken ? COOKIE_CONFIG.access.maxAge : 1,
  })

  res.cookie("Refresh-Token", refreshToken, {
    ...COOKIE_CONFIG.refresh,
    maxAge: refreshToken ? COOKIE_CONFIG.refresh.maxAge : 1,
  })

  if (!accessToken || !refreshToken) {
    return res.status(403).json({ success: false, message: "Invalid request!" })
  }

  return res.status(200).json({
    success: true,
    message: "Token refreshed successfully!!",
  })
}

export const signOut = async (req: Request, res: Response) => {
  const token = req.cookies["Access-Token"]

  if (!token) {
    throw new ExpressError({
      code: "FORBIDDEN",
      message: "Refresh token missing!!",
    })
  }

  await destroySession(token)

  res.cookie("Access-Token", "", { ...COOKIE_CONFIG.access, maxAge: 1 })
  res.cookie("Refresh-Token", "", { ...COOKIE_CONFIG.refresh, maxAge: 1 })

  return res.status(200).json({
    success: true,
    message: "Logged out successfully!!",
  })
}

export const profile = async (req: Request, res: Response) => {
  const user = Users.find(u => u.id === req.user.id)

  if (!user) {
    throw new ExpressError({
      code: "NOT_FOUND",
      message: "User not found!",
    })
  }

  return res.status(200).json({ id: user.id, email: user.email })
}
