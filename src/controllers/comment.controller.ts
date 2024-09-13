import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { isAuthenticated } from '../middlewares/auth.middleware';
import { CommentService } from '../services/comment.service';
import { CreateCommentDto } from '../dtos/comment/create-comment-dto';

const commentService = new CommentService();

export const createComment = [
  isAuthenticated,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const currentUserId = req.session.user?.id || 0;
    const postId = parseInt(req.body.postId, 10);
    const parentCommentId = req.body.parentCommentId ? parseInt(req.body.parentCommentId, 10) : null;
    const createCommentDto: CreateCommentDto = {
      ...req.body,
    };

    const newComment = await commentService.createComment(createCommentDto, currentUserId, postId, parentCommentId);

    if (req.xhr) {
      res.status(201).json(newComment);
    } else {
      res.redirect(`/posts/detail/${createCommentDto.postId}`);
    }
  })
];

export const getCommentsByPost = [
  isAuthenticated,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const postId = parseInt(req.params.postId, 10);
    const currentUserId = req.session.user?.id || 0;
    const comments = await commentService.getCommentsByPost(currentUserId, postId);
    res.status(200).json(comments);
  })
];

export const deleteComment = [
  isAuthenticated,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const commentId = parseInt(req.params.commentId, 10);
    const currentUserId = req.session.user?.id || 0;
    await commentService.deleteComment(commentId, currentUserId);
    res.status(204).send();
  })
];
