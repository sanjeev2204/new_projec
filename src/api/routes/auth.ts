import { Router, Request, Response, NextFunction } from 'express';
import { Container } from 'typedi';
import AuthService from '@/services/auth';
import { IUserInputDTO, IUserUpdateDTO } from '@/interfaces/IUser';
import middlewares from '../middlewares';
import { celebrate, Joi } from 'celebrate';
import { Logger } from 'winston';

const route = Router();



export default (app: Router) => {
  app.use('/auth', route);

  route.post(
    '/signup',
    celebrate({
      body: Joi.object({
        name: Joi.string().required(),
        email: Joi.string().required(),
        password: Joi.string().required(),
      }),
    }),
    async (req: Request, res: Response, next: NextFunction) => {
      const logger:Logger = Container.get('logger');
      logger.debug('Calling Sign-Up endpoint with body: %o', req.body );
      try {
        const authServiceInstance = Container.get(AuthService);
        const { user, token } = await authServiceInstance.SignUp(req.body as IUserInputDTO);
         
        
        return res.status(201).json({ user, token });
      } catch (e) {
        logger.error('🔥 error: %o', e);
        return next(e);
      }
    },
  );

  route.post(
    '/signin',
    celebrate({
      body: Joi.object({
        email: Joi.string().required(),
        password: Joi.string().required(),
      }),
    }),
    async (req: Request, res: Response, next: NextFunction) => {
      const logger:Logger = Container.get('logger');
      logger.debug('Calling Sign-In endpoint with body: %o', req.body);
      try {
        const { email, password } = req.body;
        const authServiceInstance = Container.get(AuthService);
        const { user, token } = await authServiceInstance.SignIn(email, password);
        return res.json({ user, token }).status(200);
      } catch (e) {
        logger.error('🔥 error: %o',  e );
        return next(e);
      }
    },
  );

  route.get('/getAllusers', async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling Sign-In endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const { users } = await authServiceInstance.getAllusers();
      return res
        .json({
          status: true,
          data: users,
          message: '',
        })
        .status(200);
    } catch (e) {
      logger.error('🔥 error: %o', e);
      return res.status(200).send({
        status: false,
        message: e.message,
        error: e,
      });
    }
  });

  route.post('/getUserByEmail', async (req: Request, res: Response, next: NextFunction) => {
    const logger: Logger = Container.get('logger');
    logger.debug('Calling Sign-In endpoint with body: %o', req.body);
    try {
      const authServiceInstance = Container.get(AuthService);
      const users = await authServiceInstance.getUserByEmail(req);
      console.log(users);

      if (users) {
        return res
          .json({
            status: true,
            data: users,
            message: 'success',
          })
          .status(200);
      } else {
        return res
          .json({
            status: false,
            data: users,
            message: 'data not available',
          })
          .status(202);
      }
    } catch (e) {
      logger.error('🔥 error: %o', e);
      return res.status(201).send({
        status: false,
        message: e.message,
        error: e,
      });
    }
  });

  route.put(
    '/updateUserDetails',
    middlewares.isAuth,
    middlewares.attachCurrentUser,
    celebrate({
      body: Joi.object({
        street: Joi.string().required(),
        city: Joi.string().required(),
        zip: Joi.string().required(),
        state: Joi.string().required(),
        street_line_2: Joi.string().required(),
      }),
    }),
    async (req: Request, res: Response, next: NextFunction) => {
      const logger: Logger = Container.get('logger');
      logger.debug('Calling Sign-In endpoint with body: %o', req.body);

      var currentUser = req.currentUser;
      console.log(currentUser);
      try {
        const authServiceInstance = Container.get(AuthService);
            const { user } = await authServiceInstance.updateUserDetails(req.body as IUserUpdateDTO, currentUser._id);
        return res.status(201).json({
          status: true,
          data: user,
      
        });
      } catch (e) {
        logger.error('🔥 error: %o', e);
        return res.status(200).send({
          status: false,
          message: e.message,
          error: e,
        });
      }
    },
  );

  route.post(
    '/changePassword',
    celebrate({
      body: Joi.object({
        email: Joi.string().required(),
        NewPassword: Joi.string().required(),
        oldpassword: Joi.string().required(),
      }),
    }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const authServiceInstance = Container.get(AuthService);
        let { user, message } = await authServiceInstance.changePassword(req.body as IUserUpdateDTO);
        return res.status(201).send({
          status: true,
          data: user,
          message: message,
        });
      } catch (e) {
        return res.status(200).send({
          status: false,
          message: e.message,
          error: e,
        });
      }
    },
  );

  route.post(
    '/resetPassword',
    celebrate({
      body: Joi.object({
        email: Joi.string().required(),
        NewPassword: Joi.string().required(),
        confirmNewPassword: Joi.string().required(),
      }),
    }),
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const authServiceInstance = Container.get(AuthService);
        let { user, message } = await authServiceInstance.resetPassword(req.body as IUserUpdateDTO);
        return res.status(201).send({
          status: true,
          data: user,
          message: message,
        });
      } catch (e) {
        return res.status(200).send({
          status: false,
          message: e.message,
          error: e,
        });
      }
    },
  );

  /**
   * @TODO Let's leave this as a place holder for now
   * The reason for a logout route could be deleting a 'push notification token'
   * so the device stops receiving push notifications after logout.
   *
   * Another use case for advance/enterprise apps, you can store a record of the jwt token
   * emitted for the session and add it to a black list.
   * It's really annoying to develop that but if you had to, please use Redis as your data store
   */
  route.post('/logout', middlewares.isAuth, (req: Request, res: Response, next: NextFunction) => {
    const logger:Logger = Container.get('logger');
    logger.debug('Calling Sign-Out endpoint with body: %o', req.body);
    try {
      //@TODO AuthService.Logout(req.user) do some clever stuff
      return res.status(200).end();
    } catch (e) {
      logger.error('🔥 error %o', e);
      return next(e);
    }
  });
};
