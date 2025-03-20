import { Request, Response } from "express"
import { z } from "zod"
import { zBodyParse } from "~/utils/z-parse"
import bcrypt from "bcrypt"
import { v4 } from "uuid"
import { ExpressError } from "~/middleware/error"
import {
  COOKIE_CONFIG,
  createJWT,
  destroySession,
  refreshAccessToken,
} from "~/utils/jwt"

const saltRounds = 10

const Users: { id: string; email: string; password: string }[] = []

export const signUp = async (req: Request, res: Response) => {
  const {
    success,
    error,
    data: input,
  } = zBodyParse(
    z.object({
      email: z.string().email(),
      password: z.string().max(30),
    }),
    req.body
  )

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

  const hashedPassword = await bcrypt.hash(input.password, saltRounds)

  Users.push({ id: v4(), email: input.email, password: hashedPassword })

  return res.status(200).json({
    message: "User created successfully!!!",
  })
}

export const signIn = async (req: Request, res: Response) => {
  const {
    success,
    error,
    data: input,
  } = zBodyParse(
    z.object({
      email: z.string().email(),
      password: z.string().max(30),
    }),
    req.body
  )

  if (!success || error) {
    throw new ExpressError({
      code: "BAD_REQUEST",
      message: "Invalid Inputs!!!",
      error: error,
    })
  }

  const user = Users.find(u => u.email === input.email)

  if (!user || !(await bcrypt.compare(input.password, user.password))) {
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
    message: "Login Successful!!",
  })
}

export const refresh = async (req: Request, res: Response) => {
  const token = req.cookies["Refresh-Token"]

  if (!token) {
    throw new ExpressError({
      code: "FORBIDDEN",
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
    message: "Logged out successfully!!",
  })
}

export const profile = async (req: Request, res: Response) => {
  return res.status(200).json(Users.find(u => u.id === req.user.id))
}
