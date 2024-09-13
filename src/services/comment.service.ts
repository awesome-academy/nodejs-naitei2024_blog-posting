import { AppDataSource } from '../config/data-source';
import { Comment } from '../entities/comment.entity';
import { PostService } from './post.service';
import { UserService } from './user.service';
import { ActionService } from './action.service';
import { ActionType } from '../constants/action-types';

const userService = new UserService();
const postService = new PostService();
const actionService = new ActionService();

export class CommentService {
  private commentRepository = AppDataSource.getRepository(Comment);

  async createComment(
    commentData: Partial<Comment>,
    userId: number,
    postId: number,
    parentCommentId: number | null
  ): Promise<Comment> {
    const user = await userService.getUserById(userId);
    const post = await postService.getPostById(userId, postId);

    if (!post) {
      throw new Error('Post not found');
    }

    if (!user) {
      throw new Error('User not found');
    }

    if (parentCommentId !== null) {
      const parent = await this.commentRepository.findOne({ where: { commentId: parentCommentId } })

      if (parent !== null) {
        const comment = this.commentRepository.create({
          ...commentData,
          user,
          post,
          parent,
        });

        return await this.commentRepository.save(comment);
      }
    }
    
    const comment = this.commentRepository.create({
      ...commentData,
      user,
      post,
    });

    // Save the comment and handle potential errors
    const savedComment = await this.commentRepository.save(comment);
    // Update post comment count only if comment creation is successful
    if (savedComment) {
      await actionService.updatePostStats(postId, true, ActionType.COMMENT);
    }
    return savedComment;
  }

  async updateComment(
    commentId: number,
    commentData: Partial<Comment>,
    userId: number
  ): Promise<Comment> {
    const comment = await this.getCommentById(commentId);

    if (!comment) {
      throw new Error('Comment not found');
    }

    if (comment.user.userId !== userId) {
      throw new Error('Unauthorized: You can only update your own comments');
    }

    // Update comment fields
    comment.content = commentData.content || comment.content;
    
    const updatedComment = await this.commentRepository.save(comment);

    return updatedComment;
  }

  async getCommentsByPost(userId: number | undefined, postId: number): Promise<Comment[]> {

    const post = await postService.getPostById(userId, postId);

    if (!post) {
      throw new Error('Post not found');
    }

    return await this.commentRepository.find({
      where: { post: { postId } },
      order: { createdAt: 'DESC' },
    });
  }

  async deleteComment(commentId: number, currentUserId: number): Promise<void> {
    const comment = await this.getCommentById(commentId);
    if (comment.user.userId !== currentUserId) {
      throw new Error('Unauthorized: You can only delete your own comments');
    }
    await actionService.updatePostStats(comment.post.postId, false, ActionType.COMMENT);
    await this.commentRepository.delete(commentId);
  }

  async getCommentById(commentId: number): Promise<Comment> {
    try {
      const comment = await this.commentRepository.findOne({
        where: { commentId },
        relations: ['user', 'post'],
      });

      if (!comment) {
        throw new Error('Comment not found');
      }

      return comment;
     } catch (error) {
        throw new Error('Comment not found');
     }
  }
}
