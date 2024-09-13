import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from 'dotenv';

config();
const TOKEN_SECRET = process.env.TOKEN_SECRET || "T0P_S3CR3T" ;

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  // Token must be assigned in header from the client-side
  // Auth Type: Bearer Token
  const authorizationHeader = req.header('Authorization');
  if (!authorizationHeader) {
    return res.status(401).json({ success: false, errors: ['Unauthorized'] });
  }
  const token = authorizationHeader.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, errors: ['Invalid token'] });
  }
};

export function getUserIdFromRequest(req: Request): number {
  const authorizationHeader = req.header('Authorization');
  if (!authorizationHeader) {
    return 0;
  }
  const token = authorizationHeader.replace('Bearer ', '');
  const decoded = jwt.verify(token, TOKEN_SECRET);
  req.user = decoded;
  return parseInt(req.user['userId']) || 0;
}
