import { BaseListTypeInfo, SessionStrategy } from "@keystone-6/core/types"
import { KeystoneOpenIdOptions } from "."

export type AuthSession<UserType extends BaseListTypeInfo, SessionData> = {
    listKey: string | number
    itemId: string
    user: UserType["item"]
    data: SessionData
}
  
export function createAuthSessionStrategy<UserType extends BaseListTypeInfo, SessionData, Session extends AuthSession<UserType, SessionData>>(options: KeystoneOpenIdOptions<UserType, SessionData>){
    // this strategy wraps the existing session strategy,
    //   and injects the requested session.user before returning
    return function(_sessionStrategy: SessionStrategy<Session>) : SessionStrategy<Session> {
        const { get, ...sessionStrategy } = _sessionStrategy
        return {
            ...sessionStrategy,
            get: async ({ context }) => {
                const session = await get({ context })
                const sudoContext = context.sudo()
                if (!session?.itemId) return

                try {
                    const user = await sudoContext.db[options.userListKey].findOne({
                        where: { id: session.itemId },
                    })
                    if (!user) return

                    return {
                        ...session,
                        itemId: session.itemId,
                        user
                    }
                } catch (e) {
                    console.error(e)
                    // WARNING: this is probably an invalid configuration
                    return
                }
            },
        }
    }
}