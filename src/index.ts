import "express-async-errors"
import express, { Express, NextFunction, Request, Response } from "express"
import cookieParser from "cookie-parser"
import { env } from "./env"
import bodyParser from "body-parser"
const app: Express = express()

import corsOptions from "./cors"
import { ERROR_CODES, ExpressError } from "./middleware/error"
import logger from "./error-logger"

app.options("*", corsOptions)
app.use(cookieParser())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

app.listen(env.PORT, () => {
  console.log(`[server]: Server is running at http://localhost:${env.PORT}`)
})

import router from "./routes"

app.use("/api", router)

app.use((req: Request, res: Response, next: NextFunction) => {
  const error = new ExpressError({
    code: "NOT_FOUND",
    message: `Route ${req.originalUrl} not found.`,
  })
  next(error)
})

app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof ExpressError) {
    const statusCode = ERROR_CODES[err.code] || 500

    return res
      .status(statusCode)
      .json({ status: statusCode, message: err.message, error: err.error })
  } else {
    logger.error("Internal Server Error", {
      message: err.message,
      stack: err.stack,
    })

    return res.status(500).json({
      status: 500,
      message: "Internal Server Error !!!",
    })
  }
})
