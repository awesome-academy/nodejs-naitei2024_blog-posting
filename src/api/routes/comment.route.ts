import { Router } from 'express';
import { createCommentApi, deleteCommentApi, getCommentsByPostApi } from '../components/comment/comment.controller';

const router = Router();

// API route to create a comment
router.post('/comments', createCommentApi);

// API route to get comments for a specific post
router.get('/posts/:postId/comments', getCommentsByPostApi);

// API route to delete a comment
router.delete('/comments/:commentId', deleteCommentApi);

export default router;
