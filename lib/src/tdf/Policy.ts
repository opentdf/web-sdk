import { v4 as uuid } from 'uuid';

import { type AttributeObject } from '../../tdf3/src/models/attribute.js';
import { type Policy } from '../../tdf3/src/models/policy.js';

export class PolicyBuilder {
  static CURRENT_VERSION = '1.1.0';

  private uuidStr = uuid();
  private dataAttributesList: AttributeObject[] = [];
  private dissemList: string[] = [];

  /**
   * Adds a group of entities, to the Policy's dissem list
   *
   * @param entities The entities will be added to the policy and
   * they will have access to the TDF
   */
  addEntities(entities: string[]): void {
    this.dissemList.push(...entities);

    // Remove any duplicates
    this.dissemList = this.dissemList.filter((elem, index, self) => {
      return index === self.indexOf(elem);
    });
  }

  /**
   *
   * Adds an Attribute object to the policy
   *
   * @param attribute will be added to the policy
   */
  addAttribute(attribute: AttributeObject): void {
    this.dataAttributesList.push(attribute);
  }

  toPolicy(): Policy {
    return {
      uuid: this.uuidStr,
      body: {
        dataAttributes: this.dataAttributesList,
        dissem: this.dissemList,
      },
    };
  }

  /**
   * Returns the JSON string of Policy object
   *
   * @return {string} [The constructed Policy object as JSON string]
   */
  toJSON(): string {
    return JSON.stringify(this.toPolicy());
  }
}
