// common/decorators/component.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const COMPONENT_KEY = 'component';
export const Component = (componentName: string) => SetMetadata(COMPONENT_KEY, componentName);
