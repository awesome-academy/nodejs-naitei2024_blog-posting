import { Router } from 'express';

import loginRouter from './login.route';
import postRouter from './post.route';
import commentRouter from './comment.route';

const router: Router = Router();

router.use('/login', loginRouter);
router.use('/posts', postRouter);
router.use('/comments', commentRouter);

export default router;
