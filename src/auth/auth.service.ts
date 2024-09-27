import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto/register-user.dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { envs } from 'src/config/envs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    

    private readonly logger = new Logger('AuthService');

    onModuleInit() {
        this.$connect;
        this.logger.log('mongoDB connected');
    }

    constructor(
        private jwtService: JwtService
      ) {
        super();
    }

    async signJwt( payload: JwtPayload){
        return this.jwtService.sign(payload);
    }

    async verifyToken(token: string) {
       try {
        const {sub, iat, exp, ...user} = await this.jwtService.verify(token, {
            secret: envs.jwtSecret
        });

        return {
            user: user,
            token: await this.signJwt(user)
        }
       } catch (error) {
        console.log(error);
        throw new RpcException({
            status: 401,
            message: 'Invalid Token'
        })
       }
    }

    async registerUser(registerUserDto: RegisterUserDto){
        try {
            const {email, name, password} = registerUserDto;

            
            //user exist?
            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                })
            }

            //create user
            const newUser = await this.user.create({
                data: {
                    name: name,
                    email: email,
                    //hash password
                    password: bcrypt.hashSync(password, 10)
                }
            });

            const {password:__, ...rest } = newUser;

             //token JWT
            return {
                user: rest,
                accessToken: await this.signJwt(rest)
            }



        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

    async login(loginUserDto: LoginUserDto) {
        try {
            const {email, password} = loginUserDto;

            
            //user exist?
            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'Email/Password not valid'
                })
            }

            //match password
            const isPasswordValid = bcrypt.compareSync(password, user.password);

            if (!isPasswordValid){
                throw new RpcException({
                    status: 400,
                    message: 'Email/Password not valid'
                })
            }

            

            const {password:__, ...rest } = user;

            //token JWT
            const payload = {userId: rest.id, userName: rest.name, userEmail: rest.email}


            return {
                user: rest,
                accessToken: await this.signJwt(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }
}
