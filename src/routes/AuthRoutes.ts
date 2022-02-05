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
import { verifyAccessToken } from '../services/JwtServices';

// eslint-disable-next-line new-cap
const router = Express.Router();

// router.post('/googleAuth', googleAuth);
router.post('/login', loginHandler);
router.post('/register', registerHandler);
router.post('/forgot-password', forgotPasswordHandler);
router.post('/reset-password/:encryptedLinkToken', resetPasswordHandler);
router.put('/verify-email', emailVerificationHandler);
router.get('/refresh-token', refreshTokenHandler);
router.post('/logout', verifyAccessToken, logoutHandler);

export default router;
