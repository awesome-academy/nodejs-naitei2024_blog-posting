import express from 'express';
import * as authController from '../controllers/auth.controller';

const router = express.Router();

router.get('/', authController.getRegister);
router.post('/', authController.postRegister);

export default router;
