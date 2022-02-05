import dotenv from 'dotenv';
dotenv.config();

import cors from 'cors';
import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
// import { ExceptionType } from './interfacesAndTypes/ExceptionTypes';
import AuthRoutes from './routes/AuthRoutes';
import UserRoutes from './routes/UserRoutes';
// import { errorMiddleware } from './middleware/ErrorMiddleware';
import { connect } from './database/mongoDBInitializer';
import passport from 'passport';
import GoogleAuthRoutes from './routes/GoogleAuthRoutes';
import './utils/googlePassport';
import session from 'express-session';
import connectRedis from 'connect-redis';
import redisClient from './database/redisClient';
// import { ExceptionType } from './interfacesAndTypes/ExceptionTypes';
// import { errorMiddleware } from './middleware/ErrorMiddleware';

const RedisStore = connectRedis(session);

console.clear();

export const runServer = () => {
  const app: Express = express();
  app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true }));

  app.use(
    session({
      store: new RedisStore({ client: redisClient, ttl: 30 * 24 * 3600 }),
      secret: process.env.SESSION_SECRET!,
      name: 'sid',
      resave: false,
      saveUninitialized: true,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
      },
    })
  );

  app.use(passport.initialize());

  app.use([
    cookieParser(process.env.CLIENT_ORIGIN),
    express.json(),
    express.urlencoded({ extended: false }),
  ]);

  app.use('/api/auth', AuthRoutes);
  app.use('/api/user', UserRoutes);
  app.use('/api/google', GoogleAuthRoutes);
  // app.use(
  //   // eslint-disable-next-line
  //   (err: ExceptionType, req: Request, res: Response, _: NextFunction) => {
  //     return errorMiddleware(err, req, res);
  //   }
  // );
  const PORT = process.env.PORT;
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT} 🚀`);
  });

  return app;
};

connect(process.env.DB_URI)
  .then(() => {
    runServer();
  })
  .catch((err) => console.log('failure on starting server', err));
