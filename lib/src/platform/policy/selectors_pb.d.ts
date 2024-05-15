import * as jspb from 'google-protobuf'



export class AttributeNamespaceSelector extends jspb.Message {
  getWithAttributes(): AttributeNamespaceSelector.AttributeSelector | undefined;
  setWithAttributes(value?: AttributeNamespaceSelector.AttributeSelector): AttributeNamespaceSelector;
  hasWithAttributes(): boolean;
  clearWithAttributes(): AttributeNamespaceSelector;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): AttributeNamespaceSelector.AsObject;
  static toObject(includeInstance: boolean, msg: AttributeNamespaceSelector): AttributeNamespaceSelector.AsObject;
  static serializeBinaryToWriter(message: AttributeNamespaceSelector, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): AttributeNamespaceSelector;
  static deserializeBinaryFromReader(message: AttributeNamespaceSelector, reader: jspb.BinaryReader): AttributeNamespaceSelector;
}

export namespace AttributeNamespaceSelector {
  export type AsObject = {
    withAttributes?: AttributeNamespaceSelector.AttributeSelector.AsObject,
  }

  export class AttributeSelector extends jspb.Message {
    getWithKeyAccessGrants(): boolean;
    setWithKeyAccessGrants(value: boolean): AttributeSelector;

    getWithValues(): AttributeNamespaceSelector.AttributeSelector.ValueSelector | undefined;
    setWithValues(value?: AttributeNamespaceSelector.AttributeSelector.ValueSelector): AttributeSelector;
    hasWithValues(): boolean;
    clearWithValues(): AttributeSelector;

    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): AttributeSelector.AsObject;
    static toObject(includeInstance: boolean, msg: AttributeSelector): AttributeSelector.AsObject;
    static serializeBinaryToWriter(message: AttributeSelector, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): AttributeSelector;
    static deserializeBinaryFromReader(message: AttributeSelector, reader: jspb.BinaryReader): AttributeSelector;
  }

  export namespace AttributeSelector {
    export type AsObject = {
      withKeyAccessGrants: boolean,
      withValues?: AttributeNamespaceSelector.AttributeSelector.ValueSelector.AsObject,
    }

    export class ValueSelector extends jspb.Message {
      getWithKeyAccessGrants(): boolean;
      setWithKeyAccessGrants(value: boolean): ValueSelector;

      getWithSubjectMaps(): boolean;
      setWithSubjectMaps(value: boolean): ValueSelector;

      getWithResourceMaps(): boolean;
      setWithResourceMaps(value: boolean): ValueSelector;

      serializeBinary(): Uint8Array;
      toObject(includeInstance?: boolean): ValueSelector.AsObject;
      static toObject(includeInstance: boolean, msg: ValueSelector): ValueSelector.AsObject;
      static serializeBinaryToWriter(message: ValueSelector, writer: jspb.BinaryWriter): void;
      static deserializeBinary(bytes: Uint8Array): ValueSelector;
      static deserializeBinaryFromReader(message: ValueSelector, reader: jspb.BinaryReader): ValueSelector;
    }

    export namespace ValueSelector {
      export type AsObject = {
        withKeyAccessGrants: boolean,
        withSubjectMaps: boolean,
        withResourceMaps: boolean,
      }
    }

  }

}

export class AttributeDefinitionSelector extends jspb.Message {
  getWithKeyAccessGrants(): boolean;
  setWithKeyAccessGrants(value: boolean): AttributeDefinitionSelector;

  getWithNamespace(): AttributeDefinitionSelector.NamespaceSelector | undefined;
  setWithNamespace(value?: AttributeDefinitionSelector.NamespaceSelector): AttributeDefinitionSelector;
  hasWithNamespace(): boolean;
  clearWithNamespace(): AttributeDefinitionSelector;

  getWithValues(): AttributeDefinitionSelector.ValueSelector | undefined;
  setWithValues(value?: AttributeDefinitionSelector.ValueSelector): AttributeDefinitionSelector;
  hasWithValues(): boolean;
  clearWithValues(): AttributeDefinitionSelector;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): AttributeDefinitionSelector.AsObject;
  static toObject(includeInstance: boolean, msg: AttributeDefinitionSelector): AttributeDefinitionSelector.AsObject;
  static serializeBinaryToWriter(message: AttributeDefinitionSelector, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): AttributeDefinitionSelector;
  static deserializeBinaryFromReader(message: AttributeDefinitionSelector, reader: jspb.BinaryReader): AttributeDefinitionSelector;
}

export namespace AttributeDefinitionSelector {
  export type AsObject = {
    withKeyAccessGrants: boolean,
    withNamespace?: AttributeDefinitionSelector.NamespaceSelector.AsObject,
    withValues?: AttributeDefinitionSelector.ValueSelector.AsObject,
  }

  export class NamespaceSelector extends jspb.Message {
    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): NamespaceSelector.AsObject;
    static toObject(includeInstance: boolean, msg: NamespaceSelector): NamespaceSelector.AsObject;
    static serializeBinaryToWriter(message: NamespaceSelector, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): NamespaceSelector;
    static deserializeBinaryFromReader(message: NamespaceSelector, reader: jspb.BinaryReader): NamespaceSelector;
  }

  export namespace NamespaceSelector {
    export type AsObject = {
    }
  }


  export class ValueSelector extends jspb.Message {
    getWithKeyAccessGrants(): boolean;
    setWithKeyAccessGrants(value: boolean): ValueSelector;

    getWithSubjectMaps(): boolean;
    setWithSubjectMaps(value: boolean): ValueSelector;

    getWithResourceMaps(): boolean;
    setWithResourceMaps(value: boolean): ValueSelector;

    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): ValueSelector.AsObject;
    static toObject(includeInstance: boolean, msg: ValueSelector): ValueSelector.AsObject;
    static serializeBinaryToWriter(message: ValueSelector, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): ValueSelector;
    static deserializeBinaryFromReader(message: ValueSelector, reader: jspb.BinaryReader): ValueSelector;
  }

  export namespace ValueSelector {
    export type AsObject = {
      withKeyAccessGrants: boolean,
      withSubjectMaps: boolean,
      withResourceMaps: boolean,
    }
  }

}

export class AttributeValueSelector extends jspb.Message {
  getWithKeyAccessGrants(): boolean;
  setWithKeyAccessGrants(value: boolean): AttributeValueSelector;

  getWithSubjectMaps(): boolean;
  setWithSubjectMaps(value: boolean): AttributeValueSelector;

  getWithResourceMaps(): boolean;
  setWithResourceMaps(value: boolean): AttributeValueSelector;

  getWithAttribute(): AttributeValueSelector.AttributeSelector | undefined;
  setWithAttribute(value?: AttributeValueSelector.AttributeSelector): AttributeValueSelector;
  hasWithAttribute(): boolean;
  clearWithAttribute(): AttributeValueSelector;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): AttributeValueSelector.AsObject;
  static toObject(includeInstance: boolean, msg: AttributeValueSelector): AttributeValueSelector.AsObject;
  static serializeBinaryToWriter(message: AttributeValueSelector, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): AttributeValueSelector;
  static deserializeBinaryFromReader(message: AttributeValueSelector, reader: jspb.BinaryReader): AttributeValueSelector;
}

export namespace AttributeValueSelector {
  export type AsObject = {
    withKeyAccessGrants: boolean,
    withSubjectMaps: boolean,
    withResourceMaps: boolean,
    withAttribute?: AttributeValueSelector.AttributeSelector.AsObject,
  }

  export class AttributeSelector extends jspb.Message {
    getWithKeyAccessGrants(): boolean;
    setWithKeyAccessGrants(value: boolean): AttributeSelector;

    getWithNamespace(): AttributeValueSelector.AttributeSelector.NamespaceSelector | undefined;
    setWithNamespace(value?: AttributeValueSelector.AttributeSelector.NamespaceSelector): AttributeSelector;
    hasWithNamespace(): boolean;
    clearWithNamespace(): AttributeSelector;

    serializeBinary(): Uint8Array;
    toObject(includeInstance?: boolean): AttributeSelector.AsObject;
    static toObject(includeInstance: boolean, msg: AttributeSelector): AttributeSelector.AsObject;
    static serializeBinaryToWriter(message: AttributeSelector, writer: jspb.BinaryWriter): void;
    static deserializeBinary(bytes: Uint8Array): AttributeSelector;
    static deserializeBinaryFromReader(message: AttributeSelector, reader: jspb.BinaryReader): AttributeSelector;
  }

  export namespace AttributeSelector {
    export type AsObject = {
      withKeyAccessGrants: boolean,
      withNamespace?: AttributeValueSelector.AttributeSelector.NamespaceSelector.AsObject,
    }

    export class NamespaceSelector extends jspb.Message {
      serializeBinary(): Uint8Array;
      toObject(includeInstance?: boolean): NamespaceSelector.AsObject;
      static toObject(includeInstance: boolean, msg: NamespaceSelector): NamespaceSelector.AsObject;
      static serializeBinaryToWriter(message: NamespaceSelector, writer: jspb.BinaryWriter): void;
      static deserializeBinary(bytes: Uint8Array): NamespaceSelector;
      static deserializeBinaryFromReader(message: NamespaceSelector, reader: jspb.BinaryReader): NamespaceSelector;
    }

    export namespace NamespaceSelector {
      export type AsObject = {
      }
    }

  }

}

