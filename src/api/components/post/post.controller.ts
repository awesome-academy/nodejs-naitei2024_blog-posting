import { Request, Response, NextFunction } from 'express';
import asyncHandler from 'express-async-handler';
import { CreatePostDto } from '../../../dtos/post/create-post.dto';
import { PostDto } from '../../../dtos/post/post.dto';
import { handleValidationErrors } from '../../../dtos/validate';
import { authenticate, getUserIdFromRequest } from '../../middleware/auth';
import { plainToClass } from 'class-transformer';
import { mapTagsToTagEntities,
        mapTagEntitiesToTags } from '../../../utils';
import { PostService } from '../../../services/post.service';

const postService = new PostService();

export const getPosts = asyncHandler(async (req: Request, res: Response) => {
  const page = parseInt(req.query.page as string, 10) || 1;
  return postService.getPostsForGuest(page)
    .then((posts) => {
      const returnDto = plainToClass(PostDto, posts, { excludeExtraneousValues: true });
      res.status(200).json(returnDto);
    })
    .catch((error: any) => {
      res.status(500).json({ errors: 'Internal server error' });
    });
});

export const createPost = [
  authenticate,
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const currentUserId = req.user['userId'];
    const createPostDto: CreatePostDto = req.body;
    if (req.body.tags) {
      const tagList = req.body.tags.split(",");
      createPostDto.tags = mapTagsToTagEntities(tagList);
    }
    const input_errors = await handleValidationErrors(createPostDto);
    if (input_errors) {
      res.status(400).json({ success: false, errors: input_errors });
      return;
    }
    try {
      const post = await postService.create(createPostDto, currentUserId);
      const returnDto = plainToClass(PostDto, post, { excludeExtraneousValues: true });
      res.status(201).json({ success: true, returnDto });
    } catch (error) {
      res.status(400).json({ success: false, errors: 'Internal server error' });
    }
  })
];

export const readPost = asyncHandler(async (req: Request, res: Response) => {
  const postId = parseInt(req.params.postId, 10);
  const currentUserId = getUserIdFromRequest(req);
  try {
    const post = await postService.getPostById(currentUserId, postId);
    const returnDto = plainToClass(PostDto, post, { strategy: 'excludeAll' });
    res.status(200).json(returnDto);
  } catch (error) {
    res.status(500).json({ errors: 'Internal server error' });
  }
});

export const updatePost = [
  authenticate,
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const postId = parseInt(req.params.postId, 10);
    const currentUserId = req.user['userId'];
    const updatePostDto: CreatePostDto = req.body;
    if (req.body.tags) {
      const tagList = req.body.tags.split(",");
      updatePostDto.tags = mapTagsToTagEntities(tagList);
    }
    try {
      const post = await postService.updatePost(postId, updatePostDto, currentUserId);
      const returnDto = plainToClass(PostDto, post, { excludeExtraneousValues: true });
      res.status(200).json({ success: true, returnDto });
    } catch (error) {
      res.status(500).json({ success: false, errors: 'Internal server error' });
    }
  })
];

export const deletePost = [
  authenticate,
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const postId = parseInt(req.params.postId, 10);
    const currentUserId = req.user['userId'];
    try {
      await postService.deletePost(postId, currentUserId);
      res.status(200).json({ success: true });
    } catch (error) {
      res.status(500).json({ success: false, errors: 'Internal server error' });
    }
  })
];

export const searchPosts = asyncHandler(async (req: Request, res: Response) => {
  const { title, content, tags } = req.query;
  const filter: { title?: string; content?: string; tags?: string[] } = {};

  if (title) filter.title = title.toString();
  if (content) filter.content = content.toString();
  if (tags) filter.tags = tags.toString().split(',');

  if (Object.keys(filter).length === 0) {
    res.status(400).json({ errors: 'Missing query params' });
  } else {
    try {
      const currentUserId = getUserIdFromRequest(req);
      const posts = await postService.getPostsByFilter(filter, currentUserId);
      const returnDto = plainToClass(PostDto, posts, { excludeExtraneousValues: true });
      res.status(200).json(returnDto);
    } catch (error) {
      res.status(500).json({ errors: 'Internal Server Error' });
    }
  }
});
