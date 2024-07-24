// common/filters/http-exception.filter.ts
import { ExceptionFilter, Catch, ArgumentsHost, HttpException, HttpStatus } from '@nestjs/common';
import { Request, Response } from 'express';
import { Logger } from '@nestjs/common';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse =
      exception instanceof HttpException ? exception.getResponse() : { message: 'Internal server error' };

    const errorMessage =
      exceptionResponse instanceof Object && 'message' in exceptionResponse
        ? (exceptionResponse as any).message
        : exceptionResponse;

    const component = (exception as any).component || 'Unknown Component';

    const errorResponse = {
      statusCode: status,
      timestamp: new Date().toISOString(),
      path: request.url,
      errorMessage,
      component,  // Ajout du nom du composant dans la réponse d'erreur

    };

    // Log the exception
    this.logger.error(
      `[${component}], HTTP Status: ${status} Error Message: ${JSON.stringify(errorResponse)}`
    );

    response.status(status).json(errorResponse);

    if (status === HttpStatus.INTERNAL_SERVER_ERROR) {
      this.sendCriticalErrorNotification(exception);
    }
  }

  private sendCriticalErrorNotification(exception: unknown) {
    // Logic for sending notifications
  }
}

