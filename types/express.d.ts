/* eslint-disable no-unused-vars */
declare namespace Express {
  interface Request {
    userId: string;
  }
}

declare namespace cookieParser {
  interface cookies {
    cookieId: string;
  }
}
