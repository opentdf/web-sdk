import { assert } from 'chai';
import { MockStream } from '../../src/utils/mock-stream';

describe('MockStream', () => {
  it('constructs empty with no arguments', () => {
    assert.instanceOf(new MockStream(), MockStream);
  });

  it('constructs with a JavaScript ArrayBuffer', () => {
    const expected = new ArrayBuffer(40);
    const actual = new MockStream(expected);
    assert.instanceOf(actual, MockStream);
  });

  // TODO - Add real tests.

  // constructor(streamContent) {
  // readStreamData(callback) {
  // readStreamEnd() {
  // end(callback) {
  // writeStreamFinish() {
  // write(chunk, callback) {
  // on(item, callback) {
});
