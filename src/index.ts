import dotenv from 'dotenv';
dotenv.config();

import cors from 'cors';
import express, { Express } from 'express';
import cookieParser from 'cookie-parser';
import passport from 'passport';

import AuthRoutes from './routes/AuthRoutes';
import UserRoutes from './routes/UserRoutes';

import { connect } from './database/mongo';

console.clear();

export const runServer = () => {
  const app: Express = express();

  app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true }));

  app.use(passport.initialize());

  app.use([
    cookieParser(process.env.CLIENT_ORIGIN),
    express.json(),
    express.urlencoded({ extended: false }),
  ]);

  app.use('/api/auth', AuthRoutes);
  app.use('/api/user', UserRoutes);

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
