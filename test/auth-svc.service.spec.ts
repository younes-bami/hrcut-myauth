import { Test, TestingModule } from '@nestjs/testing';
import { AuthSvcService } from './auth-svc.service';

describe('AuthSvcService', () => {
  let service: AuthSvcService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AuthSvcService],
    }).compile();

    service = module.get<AuthSvcService>(AuthSvcService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
