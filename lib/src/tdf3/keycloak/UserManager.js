export default class UserManager {
  constructor(config, request, token) {
    this.config = config;
    this.request = request;
    this.token = token;
  }

  async details(id) {
    const url = `/auth/admin/realms/${this.config.realm}/users/${id}`;
    const response = await this.request.get(url, {
      headers: {
        Authorization: `Bearer ${await this.token.get()}`,
      },
    });

    return response.data;
  }

  async roles(id, clients = [], includeRealmRoles = false) {
    const promises = [];
    const accessToken = await this.token.get();

    // retrieve roles from each target client
    clients.forEach(async (cid) => {
      const url = `/auth/admin/realms/${this.config.realm}/users/${id}/role-mappings/clients/${cid}/composite`;
      promises.push(
        this.request.get(url, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        })
      );
    });
    // retrieve roles from realm
    if (includeRealmRoles) {
      const url = `/auth/admin/realms/${this.config.realm}/users/${id}/role-mappings/realm/composite`;
      promises.push(
        this.request.get(url, {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        })
      );
    }

    return (await Promise.all(promises))
      .map((response) => response.data.map((role) => role.name))
      .reduce((arr, names) => {
        arr.push(...names);
        return arr;
      }, []);
  }
}
