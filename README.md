# DEMO LDAP Spring

1. Start OpenLdap Server

   ```bash
   docker-compose -f ./openldap/docker-compose.yml up -d
   ```

   This will create the ldap server (localhost:389) as well as a web interface (localhost:3800) for interacting with the
   ldap server. The login credential is user = `cn=admin,dc=example,dc=org`, pass = `admin`.

2. Start spring project

3. Hit ```/auth/ldap``` with this body for authentication:

```json
{
    "username": "",
    "password": ""
}
```

4. Hit ```/user/{userId}``` to query a user in the LDAP directory.