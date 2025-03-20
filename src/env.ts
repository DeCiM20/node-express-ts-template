import { z } from "zod"
import dotenv from "dotenv"
dotenv.config()

const transformString = (val: string | number | undefined) => {
  if (!val) return 4000
  const numberVal = typeof val === "string" ? Number(val) : val
  return isNaN(numberVal) ? 4000 : numberVal
}

const JWT_ACCESS_SECRET = "xig8RAgmcnQV4fkQG83U0DJs63cp/+8Lcj+fsn1ufqs="
const JWT_REFRESH_SECRET = "AL9tARLGtUfxQVkGMihsGJRe77nDGK4Ymh4GnIYXGF0="

const ENVs = ["development", "production"] as const

const EnvSchema = z.object({
  NODE_ENV: z.enum(ENVs).optional().default("development"),
  PORT: z.union([z.string(), z.number()]).optional().transform(transformString).default(4000),
  REDIS_URL: z.string().optional().default("redis://127.0.0.1:6379"),
  JWT_ACCESS_SECRET: z.string().optional().default(JWT_ACCESS_SECRET),
  JWT_REFRESH_SECRET: z.string().optional().default(JWT_REFRESH_SECRET),
})

export const env = EnvSchema.parse(process.env)
