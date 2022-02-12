import Express from 'express';
import {
  loginHandler,
  registerHandler,
  forgotPasswordHandler,
  resetPasswordHandler,
  emailVerificationHandler,
  refreshTokenHandler,
  logoutHandler,
} from '../controllers/AuthController';
import { googleOauthHandler } from '../controllers/GoogleAuthController';
import { verifyAccessToken } from '../services/JwtServices';

// eslint-disable-next-line new-cap
const router = Express.Router();

router.post('/login', loginHandler);
router.post('/register', registerHandler);
router.post('/forgot-password', forgotPasswordHandler);
router.post('/reset-password/:token', resetPasswordHandler);
router.get('/email-verification/:token', emailVerificationHandler);
router.get('/refresh-token', refreshTokenHandler);
router.post('/logout', verifyAccessToken, logoutHandler);
router.get('/google', googleOauthHandler);

export default router;
