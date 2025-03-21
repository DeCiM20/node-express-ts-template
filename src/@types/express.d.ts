export {} // this makes the file a module

export type SessionUserType = {
  id: string
}

declare global {
  namespace Express {
    interface Request {
      session: { user: SessionUserType }
    }
  }
}
