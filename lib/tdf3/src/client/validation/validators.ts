import { runAttributesValidation } from './validations.js';
import { AttributeValidationError, IllegalArgumentError } from '../../errors.js';

type Attribute = { attribute: string };

const AttributeValidator = (attributes: Attribute[]) => {
  try {
    runAttributesValidation(attributes);
  } catch (err) {
    if (err instanceof AttributeValidationError) {
      throw new IllegalArgumentError(err.message);
    } else {
      throw err;
    }
  }
};

export { AttributeValidator };
