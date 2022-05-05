# TDF 3.0

## API

----------- Service Builders (chainable functions) ------------

#### static create()

Constructs and returns a TDF instance.

#### setProtocol(type): Optional

- _type_ = \< 'zip' | 'zipstream' >

Sets the payload read/write protocol. Currently supports zip files and streams in zip format.
Default is zip.

#### setEncryption(opts): Required

- opts: - type: \< "split" > # Default value is "split" - cipher: \< "aes-256-gcm"> # Default value
  is "aes-256-gcm

Sets values for the payload encryption process. Currently supports only the defaults; "split" for
type, and "aes-256-gcm" for the cipher algorithm.

#### addKeyAccess(opts)

- opts: - type: \< "wrapped" > #Enumerable - attribute: \<String>. # Attribute URL to use for pubKey
  and kasUrl info - metadata: \<encrypted base64 JSON String> # Custom additional data the KAS might
  need

Adds a KAS to the array of KASs that the client can consult to get keys rewrapped. Metadata may be
needed for the policy plugins on the KAS. A typical use case for this is to pass credentials or
other user information to enpoints that the policy plugin may need to consult.

#### setPolicy(policy)

- policy: - uuid: \<uuid v4 string> # The policy identifier - body: - dataAttributes: \<Array of
  AttributeObjects> - dissem: \<Array of userIds>

The policy object is central to the TDF operation. It establishes the initial set of attributes that
an entity must have to access the encrypted data as well as the initial set of users that are
authorized.

Policies are identified by their uuid values. This should be uniquely generated on policy creation.

This initial policy object is the final one if there are no KAS plugins to modify it. If plugins
exist then this initial policy object may not reflect the actual policy the KAS uses to determine
access.

#### setEntity(entity)

- entity: - cert: \<certification string> # Signed by the EAS with its private key to assure
  validity -

#### setCustomRequestBuilder(customRequestBuilder)

The use of this function is optional.

Provides setting of any custom request builder. The custom request builder is used to allow custom
handling of the request body or headers of the request to any Key Access Service. For example, if
one wanted to add specific headers before the request is sent, this function could be used.

The custom request builder must be a function, adhering to the following specificiation:

```javascript
/*
	details.body = '.. The body of the request ..'
	details.headers = ' .. The headers of the request '
	details.method = '.. The request method, i.e., GET, POST, etc.'
	details.url = '.. The URL of the request.. '
 */
const myCustomBuilder = function (details) {
  //... implementation
};
```

#### setPublicKey(publicKey)

#### setPublicKey(publicKey)

#### setPrivateKey(privateKey)

#### setDefaultSegmentSize(segmentSizeDefault)

const DEFAULT_SEGMENT_SIZE = 1024 \* 1024;

#### setIntegrityAlgorithm(integrityAlgorithm, segmentIntegrityAlgorithm)

------ Service Interfaces ---------

#### addContent(content)

#### addContentStream(contentStream)

#### [PENDING] addToZip(fileObj)

#### async write()

#### async writeStream(outputStream) {

#### async read(tdfObj) {

#### async readStream(url, outputStream) {

======== Internal functions =========

#### async getSignature(unwrappedKeyBinary, payloadBinary, algorithmType)

Signs the payload binary with the unwrapped key split.

#### getManifest(keyInfo)

Constructs a TDF3 manifest.

#### async unwrapKey(manifest)

Uses the manifest to rewrap the policy key split. Calls a KAS.

+++++++++++ Could be utilities? +++++++++++

#### static createCipher(type)

Returns an AES-GCM crypto service

#### static async generateKeyPair()

Returns an SHA key pair

#### static async generatePolicyUuid()

Returns a UUID v4

#### static createMockStream(streamContent, isReadStream)

Returns an object that mimics the Node.js Stream object. For browser use.
