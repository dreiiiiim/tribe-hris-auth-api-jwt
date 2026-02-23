<

## Project setup

AFTRER CLONING
npm install

```
nest new apicenter-shared-auth-api

# Core Auth
npm install @nestjs/config @nestjs/jwt passport passport-jwt bcryptjs

# DTO validation
npm install class-validator class-transformer

# Swagger
npm install @nestjs/swagger swagger-ui-express

# Supabase
npm install @supabase/supabase-js

# Dev types
npm install --save-dev @types/passport-jwt @types/bcryptjs
```

## Compile and run the project

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```

## Run tests

```bash
# unit tests
$ npm run test

# e2e tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```
