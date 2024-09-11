import { AppDataSource } from '../config/data-source';
import { User } from '../entities/user.entity';

export class FollowService {
  private userRepository = AppDataSource.getRepository(User);

  async followUser(followerId: number, followedId: number): Promise<void> {
    if (followerId === followedId) {
      throw new Error('You cannot follow yourself');
    }

    const follower = await this.userRepository.findOne({
      where: { userId: followerId },
      relations: ['following'],
    });

    const followed = await this.userRepository.findOne({
      where: { userId: followedId },
    });

    if (!follower || !followed) {
      throw new Error('User not found');
    }

    if (follower.following.some(user => user.userId === followedId)) {
      throw new Error('You are already following this user');
    }

    follower.following.push(followed);
    await this.userRepository.save(follower);
  }

  async unfollowUser(followerId: number, followedId: number): Promise<void> {
    if (followerId === followedId) {
      throw new Error('You cannot unfollow yourself');
    }

    const follower = await this.userRepository.findOne({
      where: { userId: followerId },
      relations: ['following'],
    });

    if (!follower) {
      throw new Error('User not found');
    }

    follower.following = follower.following.filter(user => user.userId !== followedId);
    await this.userRepository.save(follower);
  }

  async getFollowers(userId: number): Promise<User[]> {
    const user = await this.userRepository.findOne({
      where: { userId },
      relations: ['followers'],
    });

    if (!user) {
      throw new Error('User not found');
    }

    return user.followers;
  }

  async getFollowing(userId: number): Promise<User[]> {
    const user = await this.userRepository.findOne({
      where: { userId },
      relations: ['following'],
      select: {
        following: {
          userId: true,
          username: true,
        }
      }
    });

    if (!user) {
      throw new Error('User not found');
    }

    return user.following;
  }

  async isFollowing(followerId: number, followedId: number): Promise<boolean> {
    const follower = await this.userRepository.findOne({
      where: { userId: followerId },
      relations: ['following'],
    });

    if (!follower) {
      throw new Error('User not found');
    }

    return follower.following.some(user => user.userId === followedId);
  }
}
