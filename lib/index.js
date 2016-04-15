'use strict'

const assert = require('assert')
const pick = require('lodash.pick')
const flatten = require('array-flatten')

class NotPermittedError extends Error {
  constructor () {
    super()
    this.name = 'NotPermittedError'
  }
}

module.exports = (permissions) => {
  assert(typeof permissions === 'object', 'permissions must be an object')
  const actions = permissions.actions || {}
  const roles = Object
    .keys(permissions.roles || {})
    .map((role) => (user, item) => permissions.roles[role](user, item)
      .then((hasRole) => hasRole && role))

  return function (user, item) {
    const getRoles = determineRoles(user, item)

    return {
      ensureAllowed: function (action, input) {
        return getRoles.then((roles) => ensureAllowed(roles, action, input))
      },

      filter: function (action, input) {
        return getRoles.then((roles) => filter(roles, action, input))
      },

      determineRoles () {
        return getRoles
      }
    }

    function filter (roles, action, input) {
      const fields = flatten(roles.map(filterForRole))

      if (!fields.length) throw new NotPermittedError()
      return pick(input, fields)

      function filterForRole (role) {
        return (actions[role] || [])
          .filter((a) => a.startsWith(action + ':'))
          .map((a) => a.substr((action + ':').length))
      }
    }

    function ensureAllowed (roles, action, item) {
      const allowed = !!flatten(roles.map((role) => actions[role] || []))
        .find((a) => a === action || a.startsWith(action + ':'))

      if (!allowed) return Promise.reject(new NotPermittedError())

      return Promise.resolve(item)
    }

    function determineRoles (user, item) {
      if (!user) {
        return Promise.resolve(['guest'])
      }

      return Promise
        .all(roles.map((getRole) => getRole(user, item)))
        .then((customRoles) => customRoles.filter((role) => role))
        .then((customRoles) => ['authenticated'].concat(customRoles))
    }
  }
}
