import { generateToken } from './utils'

let redirectCallback = null

export const getPasswordProtect = ({ options, ctx, storage }) => {
  const getToken = () => generateToken(typeof options.password === 'string' ? options.password : options.password[0], options.tokenSeed)

  const check = (password) => {
      if (typeof options.password === 'string') {
        return password === options.password
      } else {
        return options.password.includes(password)
      }

  }

  const passwordProtect = {

    authorise: (password) => {
        if (check(password)) {
          const token = getToken()
          storage.setCookie(options.cookieName, token)
          return true
        } else {
          return false
        }
    },

    isAuthorised: () => {
      const cookieValue = storage.getCookie(options.cookieName)
      const token = getToken()

      return cookieValue === token
    },

    removeAuthorisation: () => {
      storage.removeCookie(options.cookieName)
    },

    checkUserIfRedirect: () => {
      if (options.enabled === false) {
        return
      }

      if (options.queryString) {
        const queryPassword = ctx.route.query[options.queryString]

        if (check(queryPassword)) {
          passwordProtect.authorise(queryPassword)
          return
        }
      }

      const cookieValue = storage.getCookie(options.cookieName)

      if (ctx.route.path === options.formPath || (options.ignoredPaths || []).includes(ctx.route.path)) {
        return true
      }

      if (!cookieValue || cookieValue !== getToken()) {
        if (typeof redirectCallback === 'function') {
          redirectCallback({
            options
          })
          return
        }

        ctx.redirect(options.formPath, { previousPath: ctx.route.fullPath })
      }
    },

    registerRedirectCallback: (callback) => {
      redirectCallback = callback
    }
  }

  return passwordProtect
}
