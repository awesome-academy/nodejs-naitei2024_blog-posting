import { Router, Request, Response } from 'express';
import session from 'express-session';
import asyncHandler from 'express-async-handler';
import { Title } from '../constants';
// Import all route modules for the site here
import registerRouter from './register.route';
import loginRouter from './login.route';

const router: Router = Router();

const index = asyncHandler(async (req: Request, res: Response) => {
  const userRole = req.session.user ? req.session.user.role : null;
  res.render('index', {
    title: Title.DEFAULT,
    userRole
  });
});

const logout = asyncHandler(async (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.clearCookie('connect.sid'); // Clear the session cookie
    res.redirect('/');
  });
});

router.get('/', index);
router.get('/logout', logout);
router.use('/login', loginRouter)
router.use('/register', registerRouter);

export default router;
