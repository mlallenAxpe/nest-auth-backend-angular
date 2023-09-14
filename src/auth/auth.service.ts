import { BadRequestException, Body, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';

import * as bcrypt from 'bcryptjs';

import { CreateUserDto, LoginDto, RegisterUserDto, UpdateUserDto } from './dto';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { JwtPayload, LoginResponse, RegisterResponse } from './interfaces';
import { checkTokenDto } from './dto/check-token.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ){}
  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto
      

      const newUser = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData,
      })
      await newUser.save()
      const { password:_, ...user } = newUser.toJSON()

      return user

    } catch(error) {
      if(error.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exists`)
      }
      throw new InternalServerErrorException('Somethign bad happende')
    }
    
    //2: Guardar usuario
    //3: Generar JWT
  }

  async register(register: RegisterUserDto): Promise<LoginResponse> {
    const {confirm, ...data} = register
    if ( confirm !== data.password ) {
      throw 'Repetir password correctamente'
    }
    const registry = await this.create(register)
    const loggedIn = await this.login({email: registry.email, password: data.password})
    return loggedIn
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password } = loginDto

    const user = await this.userModel.findOne({ email })
    if( !user ) {
      throw new UnauthorizedException('Not valid credentials')
    }
    if( !bcrypt.compareSync(password, user.password) ){
      throw new UnauthorizedException('Not valid credentials')
    }

    const { password:_, ...usuario } = user.toJSON()

    return {user: usuario, token: this.getJwt({ id: user._id })}
  }
  
  findAll(): Promise<User[]> {
    return this.userModel.find({});
  }

  async findUserById( userId: string ) {
    const {password, ...user} = (await this.userModel.findById(userId)).toJSON()
    return user
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateUserDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwt(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token
  }
}
