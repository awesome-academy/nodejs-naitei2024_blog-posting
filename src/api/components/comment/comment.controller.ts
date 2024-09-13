import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { CommentService } from '../../../services/comment.service';
import { CreateCommentDto } from '../../../dtos/comment/create-comment-dto';
import { authenticate } from '../../middleware/auth';


const commentService = new CommentService();

// Create Comment API
export const createCommentApi = [
  authenticate,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const currentUserId = req.user['userId'];
    const postId = parseInt(req.body.postId, 10);
    const parentCommentId = req.body.parentCommentId ? parseInt(req.body.parentCommentId, 10) : null;
    const createCommentDto: CreateCommentDto = {
      ...req.body,
    };

    const newComment = await commentService.createComment(createCommentDto, currentUserId, postId, parentCommentId);
    res.status(201).json({ success: true, comment: newComment });
  })
];

// Get Comments by Post API
export const getCommentsByPostApi = [
  authenticate,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const postId = parseInt(req.params.postId, 10);
    const currentUserId = req.user['userId'];
    const comments = await commentService.getCommentsByPost(currentUserId, postId);
    res.status(200).json({ success: true, comments });
  })
];

// Delete Comment API
export const deleteCommentApi = [
  authenticate,
  asyncHandler(async (req: Request, res: Response): Promise<void> => {
    const commentId = parseInt(req.params.commentId, 10);
    const currentUserId = req.user['userId'];
    await commentService.deleteComment(commentId, currentUserId);
    res.status(204).json({ success: true });
  })
];

export const updateCommentApi = [
    authenticate,
    asyncHandler(async (req: Request, res: Response): Promise<void> => {
      const commentId = parseInt(req.params.commentId, 10);
      const currentUserId = req.user['userId'];
  
      const updatedComment = await commentService.updateComment(commentId, req.body, currentUserId);
  
      res.status(200).json({ success: true, comment: updatedComment });
    })
  ];
