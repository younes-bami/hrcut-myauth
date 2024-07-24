import { NotFoundException, BadRequestException, UnauthorizedException, ConflictException } from '@nestjs/common';

export function createNotFoundError(resource: string, id: string | number): NotFoundException {
  return new NotFoundException(`${resource} with ID ${id} not found`);
}

export function createBadRequestError(message: string): BadRequestException {
  return new BadRequestException(message);
}

export function createUnauthorizedError(message: string = 'Unauthorized'): UnauthorizedException {
  return new UnauthorizedException(message);
}

export function createConflictError(message: string = 'Conflict'): ConflictException {
  return new ConflictException(message);
}

export function updateConflictError(message: string = 'Conflict'): ConflictException {
  return new ConflictException(message);
}

export function updateNotFoundError(resource: string, id: string | number): NotFoundException {
  return new NotFoundException(`${resource} with ID ${id} not found`);
}