class VersionInfo {
    version:string
    clientType:string
    constructor(){
        //can add more info as needed
        this.version = "__VERSION__";
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
