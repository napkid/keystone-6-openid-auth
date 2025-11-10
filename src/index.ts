import { Router } from 'express'
import type { ErrorRequestHandler, Express, Request, Response } from 'express'
import type { BaseItem, BaseKeystoneTypeInfo, BaseListTypeInfo, KeystoneConfig, KeystoneContext, MaybePromise } from '@keystone-6/core/types'

import * as client from 'openid-client'
import { getIronSession } from 'iron-session'
import { graphql } from '@keystone-6/core'
import { createAuthSessionStrategy } from './session'

type OpenIDSessionData = {
  openIdCodeVerifier: string
  openIdAuthState: string
}

export type KeystoneOpenIdOptions<TypeInfo extends BaseListTypeInfo, SessionData> = {
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
  userListKey: TypeInfo["key"],
  sessionData: (idToken: client.IDToken, userinfo: client.UserInfoResponse, user: TypeInfo["item"]) => SessionData
  userUpsert: (userinfo: client.UserInfoResponse) => ({
    where: Partial<TypeInfo["item"]>,
    update: Partial<TypeInfo["item"]>,
    create: Partial<TypeInfo["item"]>
  }),
  postLoginRedirectUrl: string,
  errorHandler?: ErrorRequestHandler
}

const defaultConfiguration : Partial<KeystoneOpenIdOptions<any, any>> = {
  stateCookieName: 'keystone-openid-state',
  clientScope: 'email profile openid',
  clientEnablePkce: true,
  clientCodeChallengeMethod: 'S256',
  startUrl: '/auth/openid/start',
  callbackUrl: '/auth/openid/start',
  postLoginRedirectUrl: '/',
  errorHandler: (err, req, res, next) => {
    console.error(err)
    res.redirect('/404')
  }
}

export function createOpenIdAuth<TypeInfo extends BaseListTypeInfo, SessionData = any>(options: KeystoneOpenIdOptions<TypeInfo, SessionData>) : (config: KeystoneConfig) => KeystoneConfig {
  const opts : KeystoneOpenIdOptions<TypeInfo, SessionData> = {
    ...defaultConfiguration,
    ...options
  }
  const withSessionStrategy = createAuthSessionStrategy<TypeInfo, SessionData>(options)
  return config => {
    
    if(!config.session){
      throw new Error('Missing session configuration')
    }
    return ({
      ...config,
      graphql: {
        ...config.graphql,
        extendGraphqlSchema: (schema) => graphql.extend(base => {
          return {
            query: {
              authenticatedItem: graphql.field({
                type: graphql.union({
                  name: 'AuthenticatedItem',
                  types: [base.object(opts.userListKey) as graphql.ObjectType<BaseItem>],
                  resolveType: (root, context: KeystoneContext) => opts.userListKey,
                }),
                resolve (root, args, context: KeystoneContext) {
                  const { session } = context
                  if (!session) return null
                  if (!session.itemId) return null
                  if (session.listKey !== opts.userListKey) return null
          
                  return context.db[opts.userListKey]!.findOne({
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
      session: withSessionStrategy(config.session),
      server: {
        ...config.server,
        extendExpressApp: createExtendExpressApp(opts, config.server?.extendExpressApp),
      }
    })
  }
}

function createExtendExpressApp<TypeInfo extends BaseListTypeInfo, SessionData>(options: KeystoneOpenIdOptions<TypeInfo, SessionData>, extendExpressApp? : ((app: Express, context: KeystoneContext<BaseKeystoneTypeInfo>) => MaybePromise<void>)) {
  const getAuthSession = (req: Request, res: Response) => {
    return getIronSession<OpenIDSessionData>(req, res, {
      password: options.stateSessionPassword,
      cookieName: options.stateCookieName
    })
  }
  return async function<TypeInfo extends BaseKeystoneTypeInfo>(app: Express, commonContext: KeystoneContext) {
    if(extendExpressApp){
      await extendExpressApp(app, commonContext)
    }
    const oidcClientConfig = await client.discovery(
      new URL(options.serverUrl),
      options.clientId,
      options.clientMetadata,
      options.clientAuthentication,
      options.clientOptions
    )

    const router = Router()

    // OpenID callback handler
    router.get(options.callbackUrl, async (req: Request, res: Response) => {
      const session = await getAuthSession(req, res)
      if(!session){
        return res.redirect(options.postLoginRedirectUrl)
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
      const user = await commonContext.prisma[options.userListKey].upsert(options.userUpsert(userinfo))
      

      const context = await commonContext.withRequest(req, res)
      await context.sessionStrategy?.start({
        context: context,
        data: {
          listKey: options.userListKey,
          itemId: user.id,
          data: options.sessionData(idToken, userinfo, user)
        }
      })
      session.destroy()
      return res.redirect(options.postLoginRedirectUrl)
    })


    // Start authorization flow handler
    router.get(options.startUrl, async (req: Request, res: Response) => {
      const context = await commonContext.withRequest(req, res)
      if(context.session){
        return res.redirect('/')
      }
      const port = (req.socket.localPort !== 80 && req.socket.localPort !== 443)
        ? `:${req.socket.localPort}`
        : ''
      const redirect_uri = `${req.protocol}://${req.hostname}${port}${options.callbackUrl}`
      const state: string = client.randomState()
      
      
      let parameters: Record<string, string> = {
        redirect_uri,
        state,
        scope: options.clientScope
      }
      const session = await getAuthSession(req, res)

      // Setup PKCE
      if(options.clientEnablePkce){
        const code_verifier: string = client.randomPKCECodeVerifier()
        parameters.code_challenge = await client.calculatePKCECodeChallenge(code_verifier)
        parameters.code_challenge_method = options.clientCodeChallengeMethod || 'S256'
        session.openIdCodeVerifier = code_verifier
      }

      session.openIdAuthState = state
      await session.save()

      const redirectTo : URL = client.buildAuthorizationUrl(oidcClientConfig, parameters)
      return res.redirect(redirectTo.toString());
    })

    router.use(options.errorHandler!)

    app.use(router)
  }
}