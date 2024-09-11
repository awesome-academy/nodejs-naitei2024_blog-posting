import { Router } from 'express';
// Import all route modules for the site here
import homeRouter from './home.route';
import registerRouter from './register.route';
import loginRouter from './login.route';
import postRouter from './post.route';
import userRouter from './user.route';
import commentRouter from './comment.route';
import tagRouter from './tag.route';
import followRouter from './follow.route';

const router: Router = Router();

router.use('/', homeRouter);
router.use('/login', loginRouter);
router.use('/register', registerRouter);
router.use('/posts', postRouter);
router.use('/users', userRouter);
router.use('/comments', commentRouter);
router.use('/tags', tagRouter);
router.use('/follow', followRouter);

export default router;
