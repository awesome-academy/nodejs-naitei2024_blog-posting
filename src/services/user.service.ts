import bcrypt from 'bcryptjs';
import { AppDataSource } from '../config/data-source';
import { User } from '../entities/user.entity';
import { GEN_SALT_ROUND } from '../constants';

export class UserService {
  private userRepository = AppDataSource.getRepository(User);

  async getCount() {
    return await this.userRepository.count();
  }

  async getUserById(userId: number) {
    return await this.userRepository.findOne({
      where: { userId },
    });
  }

  async getUserByUsername(username: string) {
    return await this.userRepository.findOne({
      where: { username },
    });
  }

  async getUserByEmail(email: string) {
    return await this.userRepository.findOne({
      where: { email },
    });
  }

  async getUserByUsernameOrEmail(identifier: string) {
    const userByUsername = await this.getUserByUsername(identifier);
    if (userByUsername) {
      return userByUsername;
    }
    const userByEmail = await this.getUserByEmail(identifier);
    return userByEmail;
  }

  async verifyUser(username: string, password: string): Promise<boolean> {
    const user = await this.userRepository.findOne({ where: { username } });
    if (!user) {
      return false;
    }
    return await bcrypt.compare(password, user.passwordHash);
  }

  async createUser(
    username: string,
    email: string,
    password: string
  ): Promise<User> {
    const user = new User();
    user.username = username;
    user.email = email;
    user.salt = await bcrypt.genSalt(GEN_SALT_ROUND);
    user.passwordHash = await bcrypt.hash(password, user.salt);
    return await this.userRepository.save(user);
  }
}
