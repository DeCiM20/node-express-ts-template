import jwt from "jsonwebtoken"
import { env } from "~/env"
import redisClient from "~/middleware/redis"
import { validate } from "uuid"

const isDev = env.NODE_ENV === "development"

const ACCESS_TOKEN_EXPIRY = 24 * 60 * 60 // 1 Days in seconds
const REFRESH_TOKEN_EXPIRY = 30 * 24 * 60 * 60 // 30 Days in seconds

type CookieConfigType = {
  sameSite: boolean | "strict" | "lax" | "none" | undefined
  maxAge: number
  httpOnly: boolean
  secure: boolean
  path: string
}

export const COOKIE_CONFIG: {
  access: CookieConfigType
  refresh: CookieConfigType
} = {
  access: {
    sameSite: isDev ? "none" : "strict",
    maxAge: ACCESS_TOKEN_EXPIRY * 1000, // In milliseconds
    httpOnly: true,
    secure: isDev ? false : true,
    path: "/api",
  },
  refresh: {
    sameSite: isDev ? "none" : "strict",
    maxAge: REFRESH_TOKEN_EXPIRY * 1000, // In milliseconds
    httpOnly: true,
    secure: isDev ? false : true,
    path: "/api/auth/refresh",
  },
}

export const createJWT = async (
  id: string,
  uuid: string,
  type: "access" | "refresh"
) => {
  switch (type) {
    case "access":
      // Can add more data to the uid like role, permissions, etc.
      uuid = validate(uuid) ? `access-${uuid}` : uuid

      const accessToken = jwt.sign({ id, uuid }, env.JWT_ACCESS_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRY,
      })

      await redisClient.set(uuid, accessToken, {
        EX: ACCESS_TOKEN_EXPIRY,
      })
      return accessToken

    case "refresh":
      uuid = validate(uuid) ? `refresh-${uuid}` : uuid

      const refreshToken = jwt.sign({ id, uuid }, env.JWT_REFRESH_SECRET, {
        expiresIn: REFRESH_TOKEN_EXPIRY,
      })

      await redisClient.set(uuid, refreshToken, {
        EX: REFRESH_TOKEN_EXPIRY,
      })

      return refreshToken

    default:
      return ""
  }
}

type RefreshTokenType = {
  id: string
  uuid: string
}

export const refreshAccessToken = async (oldRefreshToken: string) => {
  const decoded = jwt.verify(
    oldRefreshToken,
    env.JWT_REFRESH_SECRET
  ) as RefreshTokenType

  const arr = decoded.uuid.split("-")
  arr[0] = "access"

  const accessTokenUid = arr.join("-")

  const redisAccessToken = await redisClient.get(accessTokenUid)
  const redisRefreshToken = await redisClient.get(decoded.uuid)

  // Token was hijacked or has expired
  if (redisAccessToken || !redisRefreshToken) {
    return await invalidateTokens(accessTokenUid, decoded.uuid)
  }

  const accessToken = await createJWT(decoded.id, accessTokenUid, "access")

  return { accessToken, refreshToken: oldRefreshToken }
}

export const destroySession = async (accessToken: string) => {
  const decoded = jwt.verify(
    accessToken,
    env.JWT_ACCESS_SECRET
  ) as RefreshTokenType

  const arr = decoded.uuid.split("-")
  arr[0] = "refresh"

  const refreshTokenUid = arr.join("-")

  await invalidateTokens(decoded.uuid, refreshTokenUid)
}

export const invalidateTokens = async (
  accessTokenUid: string,
  refreshTokenUid: string
) => {
  await redisClient.del(accessTokenUid)
  await redisClient.del(refreshTokenUid)
  return { accessToken: "", refreshToken: "" }
}
