// routes/follow.routes.ts

import express from 'express';
import {
  followUser,
  unfollowUser,
  getFollowers,
  getFollowing,
} from '../controllers/follow.controller';

const router = express.Router();

// Follow a user
router.post('/follow/:userId', followUser);

// Unfollow a user
router.post('/unfollow/:userId', unfollowUser);

// Get followers of a user
router.get('/:userId/followers', getFollowers);

// Get following users of a user
router.get('/:userId/following', getFollowing);

export default router;
