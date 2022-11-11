import { generateToken } from './utils'

let redirectCallback = null

export const getPasswordProtect = ({ options, ctx, storage }) => {

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
          const token = generateToken(password, options.tokenSeed)
          storage.setCookie(options.cookieName, token)
          return true
        } else {
          return false
        }
    },

    isAuthorised: () => {
      const password = typeof options.password === 'string' ? options.password : options.password[0]

      const cookieValue = storage.getCookie(options.cookieName)
      const token = generateToken(password, options.tokenSeed)

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

      if (!cookieValue || cookieValue !== generateToken(password, options.tokenSeed)) {
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
