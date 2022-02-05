/* eslint-disable no-unused-vars */
declare namespace NodeJS {
  interface ProcessEnv {
    NODE_ENV: string;
    PORT: string;
    DB_URI: string;
    CLIENT_ORIGIN: string;
    COOKIE_ACC_TOKEN: string;
    COOKIE_REFRESH_TOKEN: string;
    GOOGLE_OAUTH_REDIRECT_URL: string;
    GOOGLE_OAUTH_CLIENT_ID: string;
    GOOGLE_OAUTH_CLIENT_SECRET: string;
  }
}
