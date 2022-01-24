import redisClient from '../database/redisClient';

const getRefreshTokenKey = (userId: string) => `${userId}_refToken`;

export const set = (key: string, value: string): Promise<'OK' | null> =>
  redisClient.set(key, value);

export const get = async (key: string): Promise<string | null> =>
  redisClient.get(key);

export const del = async (key: string): Promise<number> => redisClient.del(key);

export const setRefreshTokenInRedis = async (
  userId: string,
  encryptedRefreshToken: string
) => {
  const keyName = getRefreshTokenKey(userId);
  return redisClient.set(keyName, encryptedRefreshToken);
};

export const getRefreshTokenFromRedis = (userId: string) => {
  const keyName = getRefreshTokenKey(userId);
  return redisClient.get(keyName);
};
