# Keystone 6 OpenID authentication

A Keystone 6 authentication mechanism to use OpenID Connect to authenticate and synchronize users in Keystone.

## What it is

This module allows you to add an OpenID Connect authentication flow to your Keystone CMS backend.

When your users navigates to the configured `startUrl`, it triggers an OpenID Authorization Code Flow, redirecting them to the login interface of your configured identity provider, then back to your Keystone CMS, which creates or updates an authenticated entity in your database, and creates a session.

## What it is NOT (yet)

This package is not intended to secure the API endpoints, and doesn't implement (for now) any token verification flow.

It does not provide any UI to do so, you'll have to implement it in Keystone (e.g [Custom Admin UI Pages](https://keystonejs.com/docs/guides/custom-admin-ui-pages)).

## Usage

First, you have to install the module :

```bash
npm install keystone6-openid-auth
```

Then update your Keystone configuration file to use it :

```typescript
import { createOpenIdAuth } from 'keystone6-openid-auth'

// You will need to have a session strategy configured
const sessionStrategy = statelessSessions({
  maxAge: 60 * 60 * 24 * 30,
  secret: process.env.SESSION_SECRET!,
})

// Configure the module and retrieve the withAuth function
const withAuth = createOpenIdAuth<Lists.User.TypeInfo>({
  // ...Your config here
})

// Wrap your keystone configuration using the withAuth function
export default withAuth(config({
    // ...your keystone configuration
    session: sessionStrategy,
}))
```

Ensure your authenticated entity has an unique field to store the unique identifier given by the IdP (see [the `userUpsert` configuration section](#userupsert)).

## Configuration

- `stateSessionPassword`: Secret for session encryption for OpenID state variables, 32 chars min
- `stateCookieName`: Cookie name used for OpenID state variables, destroyed afer auth. Defaults to `keystone-openid-state`
- `startUrl`: The URL on your keystone instance that will trigger the flow
- `callbackUrl`: The URL your identity provider will redirect you to
- `serverUrl`: The base URL of the identity provider, used for discovery
- `clientId`: The client ID provided by your IdP
- `clientScope`: *string* The scopes to request, space separated
- `clientEnablePkce`: *bool* Enable PKCE in flow
- `userListKey`: *string* The key of the authenticated entity in your Keystone lists
- `postLoginRedirectUrl`: *string* The URL your user will get redirected to after login
- `sessionData`: See [section below](#sessiondata)
- `userUpsert`: See [section below](#userupsert)
- `clientMetadata`: Client metadata given to `openid-client`, [see the docs](https://github.com/panva/openid-client/blob/main/docs/functions/discovery.md)
- `clientAuthentication`: Client authentication method given to `openid-client`, [see the docs](https://github.com/panva/openid-client/blob/main/docs/functions/discovery.md)
- `clientOptions`: Client options given to `openid-client`, [see the docs](https://github.com/panva/openid-client/blob/main/docs/functions/discovery.md) 
- `clientCodeChallengeMethod`: *string* Which hash method to use for PKCE, default to `S256`.
- `errorHandler` *Express.ErrorRequestHandler* error handler for the routes added by this package

### `userUpsert`

This field allows you to create or update your user from the identity provider's response. It uses the [Prisma upsert function]().

Example:

```ts
const userUpsert = (userinfo) => ({
    where: { authId: userinfo.sub },
    update: { name: userinfo.name,  },
    create: {
        authId: userinfo.sub,
        name: userinfo.name,
        email: userinfo.email
    },
})
```

### `sessionData`

This optional field allows you to configure a custom mapping of user datas to the session, for future usage.

Example usage :

```ts
const sessionData = (idToken: client.IDToken, userinfo: client.UserInfoResponse, user: YourUserType) : any => ({
    exp: idToken.exp,
    preferredUsername: userinfo.preferredUsername,
    lang: user.preferredLanguage
})
```

## Developement

To build the package, use `npm run build`.

Feel free to send PRs !

## License

This module is MIT licensed.
