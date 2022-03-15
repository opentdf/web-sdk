class VersionInfo {
  version: string | undefined;
  clientType: string;
  constructor() {
    //can add more info as needed
    this.version = process.env.PKG_VERSION;
    this.clientType = 'client-web';
  }

  getVersion() {
    return this.version;
  }
  getClientType() {
    return this.clientType;
  }
}

export const Version = new VersionInfo();
