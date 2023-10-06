import { AttributeValidationError, IllegalArgumentError } from '../../../src/errors.js';
import { AttributeObject } from '../models/attribute-set.js';

const sageGetMatch = (match: RegExpMatchArray | null) => (match ? match[0] : null);

export const ATTR_NAME_PROP_NAME = 'attr';
export const ATTR_VALUE_PROP_NAME = 'value';

// Validate attribute url protocol starts with `http://` or `https://`
const SCHEME = '(https?://)';

// validate url host be like `localhost:4000`
const HOST_PORT = '([a-z0-9][a-z0-9]{1,}:[0-9]{1,4})';

// validate url host be like `www.example.com`
const WWW_HOST = '((?:www.|(?!www))([a-z0-9][a-z0-9-]*[a-z0-9].)+[^s]{2,})';

// validate url host be like `127.0.0.1:4000`
const IP_HOST_PORT = '([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}:[0-9]{1,4})';

// validate host is one of those above
const HOST = `(${HOST_PORT}|${WWW_HOST}|${IP_HOST_PORT})`;

// validate attr  name be like `/attr/<attr_name>`
export const ATTR_NAME = `(/${ATTR_NAME_PROP_NAME}/[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]?)`;

// validate value pattern
export const ATTR_VALUE = `(/${ATTR_VALUE_PROP_NAME}/[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]?)`;

// validate attribute authority  e.g. https://example.com
const ATTR_AUTHORITY_PATTERN = `(${SCHEME}${HOST})`;

// validate attribute namespace e.g. https://example.com/attr/someattribute
const ATTR_NAMESPACE_PATTERN = `(${ATTR_AUTHORITY_PATTERN}${ATTR_NAME})`;

// validate whole attribute e.g. https://example.com/attr/someattribute/value/somevalue
export const ATTR_ATTRIBUTE_PATTERN = `^(${ATTR_NAMESPACE_PATTERN}${ATTR_VALUE})$`;

const attributeValidation = (attr: unknown) => {
  const isObject = typeof attr === 'object';
  if (!isObject) {
    throw new AttributeValidationError(`attribute should be an object`);
  }

  const { attribute } = attr as Record<string, unknown>;
  const isString = typeof attribute === 'string';
  if (!isString) {
    throw new AttributeValidationError(`attribute prop should be a string`);
  }

  if (!attribute.match(ATTR_ATTRIBUTE_PATTERN)) {
    throw new AttributeValidationError(`attribute is in invalid format [${attribute}]`);
  }

  const ATTR_NAME_PREFIX = `/${ATTR_NAME_PROP_NAME}/`;
  const ATTR_VALUE_PREFIX = `/${ATTR_VALUE_PROP_NAME}/`;
  const attrNameMatch = sageGetMatch(attribute.match(ATTR_NAME));
  const attrValueMatch = sageGetMatch(attribute.match(ATTR_VALUE));

  if (!attrNameMatch) {
    throw new AttributeValidationError(`attribute name matching error`);
  }

  if (!attrValueMatch) {
    throw new AttributeValidationError(`attribute value matching error`);
  }

  const attributeName = attrNameMatch.slice(ATTR_NAME_PREFIX.length);
  const attributeValue = attrValueMatch.slice(ATTR_VALUE_PREFIX.length);

  if (attributeName === attributeValue) {
    throw new AttributeValidationError(`attribute name should be unique with its value`);
  }

  return true;
};

type Attribute = { attribute: string };

export function runAttributesValidation(attributes: Attribute[]): attributes is AttributeObject[] {
  if (!Array.isArray(attributes)) {
    throw new AttributeValidationError('Attributes should be of type Array');
  }

  attributes.forEach(attributeValidation);
  return true;
}

export const AttributeValidator = (attributes: Attribute[]) => {
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
