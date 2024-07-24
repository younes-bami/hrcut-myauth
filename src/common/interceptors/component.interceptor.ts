import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { COMPONENT_KEY } from '../decorators/component.decorator';

@Injectable()
export class ComponentInterceptor implements NestInterceptor {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const handler = context.getHandler();
    const className = context.getClass();
    const componentName = this.reflector.get<string>(COMPONENT_KEY, handler) || this.reflector.get<string>(COMPONENT_KEY, className);

    return next.handle().pipe(
      tap({
        error: (err) => {
          if (componentName) {
            (err as any).component = componentName;
          }
        },
      }),
    );
  }
}
