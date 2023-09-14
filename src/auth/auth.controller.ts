import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginDto, RegisterUserDto, UpdateUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response.interface';
import { User } from './entities/user.entity';


@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @UseGuards( AuthGuard )
  @Get('/check-token')
  checkToken(@Request() req: Request): LoginResponse {
    const user = req['user'] as User;
    return {
      user,
      token: this.authService.getJwt({ id: user._id })
    }
  }

  @Post('/register')
  register(@Body() RegisterUserDto: RegisterUserDto) {
    return this.authService.register(RegisterUserDto)
  }


  @Post('/login')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto)
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() req: Request ) {
    /* const user = req['user']
    return user */
    return this.authService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.authService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto: UpdateUserDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
