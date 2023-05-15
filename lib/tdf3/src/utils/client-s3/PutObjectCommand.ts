import {
  type PutObjectCommandInput,
} from '@aws-sdk/client-s3';

import { BodyDataTypes } from '../aws-lib-storage/types.js';

export class PutObjectCommand {
  input: PutObjectCommandInput & { Body: BodyDataTypes}

  constructor(params : PutObjectCommandInput & { Body: BodyDataTypes }) {
    this.input = params;
  }
}