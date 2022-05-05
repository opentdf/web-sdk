import HttpRequest from './http-request';

/**
 * An AuthProvider encapsulates all logic necessary to authenticate to a backend service, in the
 * vein of <a href="https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/Credentials.html">AWS.Credentials</a>.
 * <br/><br/>
 * The client will call into its configured AuthProvider to decorate remote TDF service calls with necessary
 * authentication info. This approach allows the client to be agnostic to the auth scheme, allowing for
 * methods like identify federation and custom service credentials to be used and changed at the developer's will.
 * <br/><br/>
 * This class is not intended to be used on its own. See the documented subclasses for public-facing implementations.
 * <ul>
 * <li><a href="EmailCodeAuthProvider.html">EmailCodeAuthProvider</li>
 * <li><a href="GoogleAuthProvider.html">GoogleAuthProvider</li>
 * <li><a href="O365AuthProvider.html">O365AuthProvider</li>
 * <li><a href="OutlookAuthProvider.html">OutlookAuthProvider</li>
 * <li><a href="VirtruCredentialsAuthProvider.html">VirtruCredentialsAuthProvider</li>
 * </ul>
 */
abstract class AuthProvider {
  /**
   * Augment the provided http request with custom auth info to be used by backend services.
   *
   * @param httpReq - Required. An http request pre-populated with the data public key.
   */
  abstract injectAuth(httpReq: HttpRequest): Promise<void>;
}

export default AuthProvider;
