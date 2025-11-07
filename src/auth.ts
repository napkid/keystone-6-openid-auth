import { Router } from 'express'
import type { Express, Request, Response } from 'express'
import type { BaseItem, BaseKeystoneTypeInfo, KeystoneConfig, KeystoneContext } from '@keystone-6/core/types'

import * as client from 'openid-client'
import { getIronSession } from 'iron-session'
import { graphql } from '@keystone-6/core'

interface OpenIDSessionData {
  openIdCodeVerifier: string
  openIdAuthState: string
}

export type KeystoneOpenIDConfiguration<UserType> = {
  stateSessionPassword: string
  stateCookieName: string
  serverUrl: string
  clientId: string,
  clientMetadata?: string
  clientAuthentication?: client.ClientAuth,
  clientOptions?: client.DiscoveryRequestOptions,
  clientScope: string,
  clientEnablePkce: boolean,
  clientCodeChallengeMethod?: string
  startUrl: string,
  callbackUrl: string,
  userListKey: string,
  userUpsert: (userinfo: client.UserInfoResponse) => ({
    where: Partial<UserType>,
    update: Partial<UserType>,
    create: Partial<UserType>
  })
}

export function createOpenIdAuth<UserType>(openidConfig: KeystoneOpenIDConfiguration<UserType>) : (config: KeystoneConfig) => KeystoneConfig {
  
  
  return config => ({
    ...config,
    graphql: {
      ...config.graphql,
      extendGraphqlSchema: (schema) => graphql.extend(base => {
        return {
          query: {
            authenticatedItem: graphql.field({
              type: graphql.union({
                name: 'AuthenticatedItem',
                types: [base.object(openidConfig.userListKey) as graphql.ObjectType<BaseItem>],
                resolveType: (root, context: KeystoneContext) => openidConfig.userListKey,
              }),
              resolve (root, args, context: KeystoneContext) {
                const { session } = context
                if (!session) return null
                if (!session.itemId) return null
                if (session.listKey !== openidConfig.userListKey) return null
        
                return context.db[openidConfig.userListKey]!.findOne({
                  where: {
                    id: session.itemId,
                  },
                })
              },
            }),
          }
        }
      })(config.graphql?.extendGraphqlSchema?.(schema) || schema)
    },
    server: {
      ...config.server,
      extendExpressApp: createExtendExpressApp(openidConfig),
    }
  })
}

function createExtendExpressApp<UserType>(openidConfig: KeystoneOpenIDConfiguration<UserType>) {
  const getAuthSession = (req: Request, res: Response) => {
    return getIronSession<OpenIDSessionData>(req, res, {
      password: openidConfig.stateSessionPassword,
      cookieName: openidConfig.stateCookieName
    })
  }
  return async (app: Express, commonContext: KeystoneContext<BaseKeystoneTypeInfo>) => {
    const oidcClientConfig = await client.discovery(
      new URL(openidConfig.serverUrl),
      openidConfig.clientId,
      openidConfig.clientMetadata,
      openidConfig.clientAuthentication,
      openidConfig.clientOptions
    )

    const router = Router()

    router.get(openidConfig.callbackUrl, async (req: Request, res: Response) => {

      const session = await getAuthSession(req, res)
      if(!session){
        return res.redirect('/')
      }

      const tokens = await client.authorizationCodeGrant(oidcClientConfig, new URL(`${req.protocol}://${req.get('host')}${req.originalUrl}`), {
        pkceCodeVerifier: session.openIdCodeVerifier,
        expectedState: session.openIdAuthState,
      })

      const idToken = tokens.claims();
      if(!idToken){
        return null;
      }
      const userinfo = await client.fetchUserInfo(oidcClientConfig, tokens.access_token, idToken.sub)
      const user = await commonContext.prisma[openidConfig.userListKey].upsert(openidConfig.userUpsert(userinfo))
      

      const context = await commonContext.withRequest(req, res)
      await context.sessionStrategy?.start({
        context: context,
        data: {
          listKey: openidConfig.userListKey,
          itemId: user.id,
          data: user
        }
      })
      session.destroy()
      res.redirect('/')
    })


    router.get(openidConfig.startUrl, async (req: Request, res: Response) => {
      const context = await commonContext.withRequest(req, res)
      if(context.session){
        return res.redirect('/')
      }
      const port = (req.socket.localPort !== 80 && req.socket.localPort !== 443)
        ? `:${req.socket.localPort}`
        : ''
      const redirect_uri = `${req.protocol}://${req.hostname}${port}${openidConfig.callbackUrl}` //'http://localhost:3000/auth/login/callback'
      const state: string = client.randomState()
      
      
      let parameters: Record<string, string> = {
        redirect_uri,
        state,
        scope: openidConfig.clientScope
      }
      const session = await getAuthSession(req, res)

      // Setup PKCE
      if(openidConfig.clientEnablePkce){
        const code_verifier: string = client.randomPKCECodeVerifier()
        parameters.code_challenge = await client.calculatePKCECodeChallenge(code_verifier)
        parameters.code_challenge_method = openidConfig.clientCodeChallengeMethod || 'S256'
        session.openIdCodeVerifier = code_verifier
      }

      session.openIdAuthState = state
      await session.save()

      const redirectTo : URL = client.buildAuthorizationUrl(oidcClientConfig, parameters)
      return res.redirect(redirectTo.toString());
    })

    app.use(router)
  }
}