import { registerDecorator, ValidationOptions, ValidatorConstraint, ValidatorConstraintInterface, ValidationArguments } from 'class-validator';
import * as libphonenumber from 'libphonenumber-js';

@ValidatorConstraint({ async: false })
export class IsMoroccanPhoneNumberConstraint implements ValidatorConstraintInterface {
  validate(phoneNumber: any, args: ValidationArguments) {
    // Vérifiez que le numéro est valide et qu'il s'agit d'un numéro marocain
    if (libphonenumber.isValidPhoneNumber(phoneNumber, 'MA')) {
      const parsedNumber = libphonenumber.parsePhoneNumber(phoneNumber, 'MA');
      return parsedNumber && parsedNumber.country === 'MA';
    }
    return false;
  }

  defaultMessage(args: ValidationArguments) {
    return 'Le numéro de téléphone ($value) n\'est pas valide ou n\'appartient pas au Maroc!';
  }
}

export function IsMoroccanPhoneNumber(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsMoroccanPhoneNumberConstraint,
    });
  };
}
