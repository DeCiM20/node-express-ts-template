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
import passport from "passport"
import { Strategy as GoogleStrategy } from "passport-google-oauth2"
import { Strategy as GithubStrategy } from "passport-github2"
import { env } from "~/env"
import redisClient from "~/middleware/redis"

const saltRounds = 10

const Users: { id: string; email: string; password: string }[] = []

interface UserDataGoogle {
  id: string
  displayName: string
  name: {
    givenName: string
    familyName: string
  }
  email: string
  photos: { value: string; type: string }[]
  picture: string
}

interface UserDataGithub {
  id: string
  displayName: string
  username: string
  profileUrl: string
  _json: { email: string | null }
}

passport.use(
  new GoogleStrategy(
    {
      clientID: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
      callbackURL: `http://localhost:4000/api/auth/google/callback`,
      passReqToCallback: true,
    },
    async function (
      req: Request,
      accessT: string,
      refToken: string,
      profile: UserDataGoogle,
      done: unknown
    ) {
      try {
        let user = Users.find(u => u.email === profile.email)

        if (!user) {
          const _user = { id: v4(), email: profile.email, password: "" }
          Users.push()
          user = _user
        }

        const uuid = v4()

        const accessToken = await createJWT(user.id, uuid, "access")
        const refreshToken = await createJWT(user.id, uuid, "refresh")

        req.res?.cookie("Access-Token", accessToken, COOKIE_CONFIG.access)
        req.res?.cookie("Refresh-Token", refreshToken, COOKIE_CONFIG.refresh)

        return req.res?.redirect("http://localhost:3000/dashboard")
      } catch (e) {
        return req.res?.status(400).json({
          status: 400,
          message: "Error authenticating with google!",
        })
      }
    }
  )
)

passport.use(
  new GithubStrategy(
    {
      clientID: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET,
      callbackURL: `http://localhost:4000/api/auth/github/callback`,
      passReqToCallback: true,
    },
    async function (
      req: Request,
      accessT: string,
      refToken: string,
      profile: UserDataGithub,
      done: unknown
    ) {
      try {
        const email = profile._json.email

        if (!email) {
          return req.res?.status(400).json({
            status: 400,
            message:
              "Email address not fount! Please make sure that you have have set your email address to public! You can change it from https://github.com/settings/emails",
          })
        }

        let user = Users.find(u => u.email === email)

        if (!user) {
          const _user = { id: v4(), email: email, password: "" }
          Users.push(_user)
          user = _user
        }

        const uuid = v4()

        const accessToken = await createJWT(user.id, uuid, "access")
        const refreshToken = await createJWT(user.id, uuid, "refresh")

        req.res?.cookie("Access-Token", accessToken, COOKIE_CONFIG.access)
        req.res?.cookie("Refresh-Token", refreshToken, COOKIE_CONFIG.refresh)

        return req.res?.redirect("http://localhost:3000/dashboard")
      } catch (e) {
        return req.res?.status(400).json({
          status: 400,
          message: "Error authenticating with Github!",
        })
      }
    }
  )
)

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
  return res.status(200).json(Users.find(u => u.id === req.session.user.id))
}
