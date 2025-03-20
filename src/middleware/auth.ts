import { NextFunction, Request, Response } from "express"
import { ExpressError } from "./error"
import jwt from "jsonwebtoken"
import { env } from "~/env"
import { SessionUserType } from "~/@types/express"

async function readToken(token: string): Promise<SessionUserType> {
  return new Promise((res, rej) => {
    if (!token) return rej()
    jwt.verify(token, env.JWT_ACCESS_SECRET, function (err, user) {
      if (err) {
        return rej()
      }
      return res(user as SessionUserType)
    })
  })
}

const protectedRoute = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = req.cookies["Access-Token"]
    const user = await readToken(token)
    req.user = user
    next()
  } catch (e) {
    throw new ExpressError({
      code: "UNAUTHORIZED",
      message: "Unauthorized access - Log in to access the resource!!",
    })
  }
}

const verifyRefresh = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const token: string | undefined = req.cookies["Refresh-Token"]

  if (!token) {
    throw new ExpressError({
      code: "BAD_REQUEST",
      message: "Refresh token missing!!",
    })
  }

  jwt.verify(token, env.JWT_REFRESH_SECRET, function (err, user) {
    if (err) {
      throw new ExpressError({
        code: "BAD_REQUEST",
        message: "Invalid refresh token!!",
      })
    }

    req.user = user as SessionUserType
    next()
  })
}

export { protectedRoute, verifyRefresh }
