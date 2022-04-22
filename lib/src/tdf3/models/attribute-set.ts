import { Validator } from 'jsonschema';

const verbose = false;

type AttributeObject = {
  attribute: string;
  kasUrl: string;
  pubKey: string;
  displayName?: string;
  isDefault?: boolean;
  jwt?: string;
};

const ATTRIBUTE_OBJECT_SCHEMA = {
  id: '/AttributeObject',
  type: 'object',
  properties: {
    attribute: { type: 'string' },
    displayName: { type: 'string' },
    isDefault: { type: 'boolean' },
    pubKey: { type: 'string' },
    kasUrl: { type: 'string' },
    jwt: { type: 'string' },
  },
  required: ['attribute', 'pubKey', 'kasUrl'],
  additionalProperties: false,
};

const validator = new Validator();

class AttributeSet {
  attributes: AttributeObject[];

  defaultAttribute?: AttributeObject;

  constructor() {
    this.attributes = [];
    this.defaultAttribute = null;
  }

  /**
   * Check if attribute is in the list
   * @param attribute URL of the attribute
   * @return if attribute is in the set
   */
  has(attribute = ''): boolean {
    // This could be much more elegant with something other than an
    // array as the data structure. This is OK-ish only because the
    // expected size of the data structure is small
    // console.log(">>> ----- Has Attribute" + attribute);
    return this.attributes.reduce((acc, attrObj) => {
      return acc || attrObj.attribute === attribute;
    }, false);
  }

  /**
   * Get an attribute by URL
   * @param  attribute URL of the attribute
   * @return attribute in object form, if found
   */
  get(attribute = ''): AttributeObject | null {
    // This could be much more elegant with something other than an
    // array as the data structure. This is OK-ish only because the
    // expected size of the data structure is small
    // console.log(">>> ----- Get Attribute" + attribute);
    const result = this.attributes.filter((attrObj) => attrObj.attribute == attribute);
    return result.length > 0 ? result[0] : null;
  }

  /**
   * Get all the attributes.
   * @return default attribute in object form or null
   */
  getDefault(): AttributeObject | null {
    return this.defaultAttribute;
  }

  /**
   * Get the default attribute, if it exists.
   * @return return all the attribute urls
   */
  getUrls(): string[] {
    return this.attributes.map((attr) => attr.attribute);
  }

  /**
   * Add an attribute to the set. Should be idempotent.
   * @param attrObj AttributeObject to add, in non-JWT form
   * @return the attribute object if successful, or null
   */
  addAttribute(attrObj: AttributeObject): AttributeObject | null {
    // Check shape of object.  Reject semi-silently if malformed.
    const result = validator.validate(attrObj, ATTRIBUTE_OBJECT_SCHEMA);
    if (!result.valid) {
      // TODO: Determine if an error should be thrown
      // console.log("WARNING - AttributeSet.addAttribute: AttributeObject is malformed. AddAttribute failed:");
      if (verbose) console.log(attrObj);
      return null;
    }
    // Check for duplicate entries to assure idempotency.
    if (this.has(attrObj.attribute)) {
      // This may be a common occurance, so only un-comment this log message
      // if you want verbose mode.
      // console.log(`Attribute ${attrObj.attribute} is already loaded.`);
      return null; // reject silently
    }

    if (attrObj.isDefault === true) {
      if (this.defaultAttribute && this.defaultAttribute.attribute !== attrObj.attribute) {
        // Remove the existing default attribute to make room for the new one
        this.deleteAttribute(this.defaultAttribute.attribute);
      }
      this.defaultAttribute = attrObj;
    }
    this.attributes.push(attrObj);
    return attrObj;
  }

  /**
   * Delete an attribute from the set. Should be idempotent.
   * @param attrUrl - URL of Attribute object to delete.
   * @return The attribute object if successful or null if not
   */
  deleteAttribute(attrUrl = ''): AttributeObject | null {
    const deleted = this.get(attrUrl);
    if (deleted) {
      this.attributes = this.attributes.filter((attrObj) => attrObj.attribute != attrUrl);
    }
    return deleted;
  }

  /**
   * Add a list of attributes in object form
   * @param  attributes List of attribute objects as provided in an EntityObject
   * @param  easPublicKey EAS public key for decrypting the JWTs
   * @return list of attribute objects
   */
  addAttributes(attributes: AttributeObject[] = []): AttributeObject[] {
    return attributes
      .map((attrObj) => {
        return this.addAttribute(attrObj); // Returns promise
      })
      .filter((x) => x);
  }
}

export { AttributeSet, AttributeObject };
