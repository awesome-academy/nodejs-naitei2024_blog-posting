import { In, Not } from 'typeorm';
import { AppDataSource } from '../config/data-source';
import { PostVisibility } from '../constants/post-visibility';
import { CreatePostDto } from '../dtos/post/create-post.dto';
import { Post } from '../entities/post.entity';
import { PostStats } from '../entities/post-stats.entity';
import { Tag } from '../entities/tag.entity';
import { UserService } from './user.service';
import { TagService } from './tag.service';
import { PAGE_SIZE } from '../constants/post-constant';
import { extractIMG } from '../utils';
import Fuse from 'fuse.js'
import { User } from '../entities/user.entity';

const userService = new UserService();
const tagService = new TagService();

export class PostService {
  private postRepository = AppDataSource.getRepository(Post);
  private postStatsRepository = AppDataSource.getRepository(PostStats);
  private userRepository = AppDataSource.getRepository(User);

  async getPostById(userId: number | undefined, postId: number) {
    const post = await this.postRepository.findOne({
      where: { postId },
      relations: ['user', 'stats', 'actions', 'comments', 'tags']
    });

    if (!post) {
      throw new Error('Post not found');
    }

    if (post.visible !== PostVisibility.PUBLIC && post.visible !== PostVisibility.PINNED) {
      if (!userId || post.user.userId !== userId) {
        throw new Error('Post not found');
      }
    }
    return post;
  }

  async getPostsByUserId(userId: number, currentUserId: number | undefined) {
    const pinnedPosts = await this.postRepository.find({
      where: { user: { userId }, visible: PostVisibility.PINNED },
      order: { createdAt: 'DESC' },
    });
    
    if (userId !== currentUserId) {
      const publicPosts = await this.postRepository.find({
        where: { user: { userId }, visible: PostVisibility.PUBLIC },
        order: { createdAt: 'DESC' },
      });

      const posts = [...pinnedPosts, ...publicPosts];
      return posts;
    }

    const remainingPosts = await this.postRepository.find({
      where: { user: { userId }, visible: Not(PostVisibility.PINNED) },
      order: { createdAt: 'DESC' },
    });
      
    const posts = [...pinnedPosts, ...remainingPosts];
    return posts;
  }
    
  async getPostsForGuest(page: number = 1) {
    const pageSize = PAGE_SIZE;
    const offset = (page - 1) * pageSize;

    const posts = await this.postRepository.find({
      where: { visible: PostVisibility.PUBLIC },
      relations: ['user'],
      order: { createdAt: 'DESC' },
      skip: offset,
      take: pageSize,
    });

    return posts;
  }

  async getPostsByVisibility(visibility: PostVisibility) {
    return await this.postRepository.find({
      where: { visible: visibility },
      relations: ['user', 'tags'],
    });
  }

  async getPostsByTag(tagId: number) {
    return await this.postRepository.find({
      where: {
        visible: PostVisibility.PUBLIC,
        tags: { id: tagId }
      },
      relations: ['user', 'tags'],
    });
  }

  async getPostsByPattern(pattern: string, currentUserId: number | undefined) {
    const posts = await this.postRepository.find({
      relations: ['user'],
      where: [
        { visible: PostVisibility.PUBLIC },
        { user: { userId: currentUserId } }
      ]
    });
    const fuse = new Fuse(posts, {
      keys: [
        'title',
        'content',
        'user.username',
        'tags.name'
      ],
      useExtendedSearch: true, //unix-like search: ' ' = AND, '|'=OR
      threshold: 0, //threshold of 0 requires a perfect match
      ignoreLocation: true,
    });
    const result = fuse.search(pattern);
    return result.map((item) => item.item);
  }

  async getTopPosts(limit: number, userId?: number) {
    const topPosts = await this.postRepository
      .createQueryBuilder('post')
      .innerJoinAndSelect('post.stats', 'stats')
      .innerJoinAndSelect('post.user', 'user')
      .where('post.visible = :visibility OR user.userId = :userId', {
        visibility: PostVisibility.PUBLIC,
        userId,
      })
      .addSelect('(stats.views * 2 + stats.likes * 3 + stats.comments * 4) as score') // Calculate score
      .orderBy('score', 'DESC')
      .limit(limit)
      .getMany();

    return topPosts;
  }

  async getFYPPosts(userId: number, page: number = 1) {
    const pageSize = PAGE_SIZE;
    const offset = (page - 1) * pageSize;
  
    // Retrieve the current user's following list
    const following = await this.userRepository.findOne({
      where: { userId },
      relations: ['following']
    });
  
    if (!following) {
      throw new Error('User not found');
    }
  
    const followingIds = following.following.map(user => user.userId);
  
    // Find posts from the users the current user is following, as well as their own posts
    const posts = await this.postRepository.find({
      relations: ['user'],
      where: [
        // Posts from followed users
        { user: { userId: In(followingIds) }, visible: In([PostVisibility.PUBLIC, PostVisibility.PINNED]) },
        // Posts from the current user
        { user: { userId } }
      ],
      order: { createdAt: 'DESC' },
      skip: offset,
      take: pageSize,
    });
  
    return posts;
  }
  

  async create(createPostDto: CreatePostDto, userId: number): Promise<Post> {
    const user = await userService.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }
    if (createPostDto.tags) {
      const postTags = await tagService.associateTagsWithPost(createPostDto.tags);
      createPostDto.tags = postTags;
    }
    const post = await this.postRepository.create({
      ...createPostDto,
      imageUrl: extractIMG(createPostDto.content),
      user,
    });
    // Create PostStats along with new post
    // Save the post record first
    const savedPost = await this.postRepository.save(post);
    // After saving the post, create the stats
    if (savedPost) {
      const postStats = new PostStats();
      postStats.id = savedPost.postId;
      await this.postStatsRepository.save(postStats);
    }
    return savedPost;
  }
    
  async updatePost(postId: number, updatePostDto: CreatePostDto, userId: number): Promise<Post> {
    const post = await this.getPostById(userId, postId);
  
    if (!post) {
      throw new Error('Post not found');
    }
  
    if (post.user.userId !== userId) {
      throw new Error('Unauthorized');
    }
    this.postRepository.merge(post, updatePostDto);
    post.imageUrl = extractIMG(updatePostDto.content);
    if (updatePostDto.tags) {
      post.tags = await tagService.associateTagsWithPost(updatePostDto.tags);
    }
    return this.postRepository.save(post);
  }

  async deletePost(postId: number, userId: number) {
    const post = await this.getPostById(userId, postId);

    if (!post) {
      throw new Error('Post not found');
    }

    if (post.user.userId !== userId) {
      throw new Error('Unauthorized');
    }
    return this.postRepository.remove(post);
  }

  async updatePostVisibility(postId: number, visibility: PostVisibility, userId: number) {
    const post = await this.getPostById(userId, postId);
    if (!post) {
      throw new Error('Post not found or not authorized');
    }
    post.visible = visibility;
    await this.postRepository.save(post);
  }
  
}
