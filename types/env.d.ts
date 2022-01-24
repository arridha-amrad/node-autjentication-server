/* eslint-disable no-unused-vars */
declare namespace NodeJS {
  interface ProcessEnv {
    NODE_ENV: string;
    PORT: string;
    DB_URI: string;
    CLIENT_ORIGIN: string;
    COOKIE_NAME: string;
    COOKIE_ID: string;
  }
}
