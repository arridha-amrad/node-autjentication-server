import express from 'express';
import passport from 'passport';
import googleAuthController from '../controllers/GoogleAuthController';

// eslint-disable-next-line new-cap
const router = express.Router();

router.get('/oauth/login', passport.authenticate('google'));

router.get(
  '/oauth/callback',
  passport.authenticate('google', {
    failureRedirect: `${process.env.CLIENT_ORIGIN}/login`,
    session: false,
  }),
  async (req, res) => await googleAuthController(req, res)
);

export default router;
