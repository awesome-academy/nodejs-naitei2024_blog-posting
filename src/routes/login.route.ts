import express from 'express';
import * as authController from '../controllers/auth.controller';

const router = express.Router();

router.get('/', authController.getLogin);
router.post('/', authController.postLogin);

export default router;
