import { Request, Response } from 'express';
import { FollowService } from '../services/follow.service';
import asyncHandler from 'express-async-handler';
import i18next from 'i18next';
import { isAuthenticated } from '../middlewares/auth.middleware';

const { t } = i18next;
const followService = new FollowService();

// Follow a user
export const followUser = [
  isAuthenticated,
  asyncHandler(async (req: Request, res: Response) => {
    const followerId = req.session.user?.id || 0;
    const followedId = parseInt(req.params.userId, 10);

    try {
      await followService.followUser(followerId, followedId);
      req.flash('flashMessage', t('message.followSuccess'));
      res.redirect(`/users/${followedId}`);
    } catch (error) {
      console.error(error);
      const err = error as Error;
      req.flash('flashMessage', err.message);
      res.redirect(`/users/${followedId}`);
    }
  }),
];

// Unfollow a user
export const unfollowUser = [
  isAuthenticated,
  asyncHandler(async (req: Request, res: Response) => {
    const followerId = req.session.user?.id || 0;
    const followedId = parseInt(req.params.userId, 10);

    try {
      await followService.unfollowUser(followerId, followedId);
      req.flash('flashMessage', t('message.unfollowSuccess'));
      res.redirect(`/users/${followedId}`);
    } catch (error) {
      console.error(error);
      res.redirect(`/users/${followedId}`);
    }
  }),
];

// Get followers of a user
export const getFollowers = asyncHandler(async (req: Request, res: Response) => {
  const userId = parseInt(req.params.userId, 10);

  try {
    const followers = await followService.getFollowers(userId);
    res.render('user/followers', {
      followers,
      title: t('title.followers'),
      flashMessage: req.flash('flashMessage'),
    });
  } catch (error) {
    console.error(error);
    res.status(500).send(t('error.serverError'));
  }
});

// Get following users of a user
export const getFollowing = asyncHandler(async (req: Request, res: Response) => {
  const userId = parseInt(req.params.userId, 10);

  try {
    const following = await followService.getFollowing(userId);
    res.render('user/following', {
      following,
      title: t('title.following'),
      flashMessage: req.flash('flashMessage'),
    });
  } catch (error) {
    console.error(error);
    res.status(500).send(t('error.serverError'));
  }
});
