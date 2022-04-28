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

// validate attr name be like `/attr/<attr_name>`
export const ATTR_NAME = `(/${ATTR_NAME_PROP_NAME}/[a-z0-9]+)`;

// validate value pattern
export const ATTR_VALUE = `(/${ATTR_VALUE_PROP_NAME}/[a-z0-9]+)`;

// validate attribute authority  e.g. https://example.com
const ATTR_AUTHORITY_PATTERN = `(${SCHEME}${HOST})`;

// validate attribute namespace e.g. https://example.com/attr/someattribute
const ATTR_NAMESPACE_PATTERN = `(${ATTR_AUTHORITY_PATTERN}${ATTR_NAME})`;

// validate whole attribute e.g. https://example.com/attr/someattribute/value/somevalue
export const ATTR_ATTRIBUTE_PATTERN = `^(${ATTR_NAMESPACE_PATTERN}${ATTR_VALUE})$`;
