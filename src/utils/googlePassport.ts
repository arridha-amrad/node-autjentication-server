import GooglePassport from 'passport-google-oauth20';
import passport from 'passport';

const GoogleStrategy = GooglePassport.Strategy;

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_OAUTH_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_OAUTH_REDIRECT_URL,
      scope: ['profile'],
    },
    (_, __, profile, cb) => cb(null, profile)
  )
);
