/* global describe, it */
'use strict'

const guard = require('../lib')
const chai = require('chai').use(require('chai-as-promised'))
const expect = chai.expect

// fixtures
const guest = undefined
const owner = { _id: 1 }
const unrelated = { _id: 2 }

const item = {
  _id: 1,
  firstName: 'Maximilian',
  lastName: 'Schmitt',
  email: 'maximilian.schmitt@googlemail.com',
  password: '12345678'
}

const permissions = () => {
  const exports = {}

  exports.roles = {
    owner (authenticatedUser, user) {
      return Promise.resolve(
        String(authenticatedUser._id) === String(user._id)
      )
    }
  }

  exports.actions = {
    guest: [
      'create:firstName',
      'create:lastName',
      'create:email',
      'create:password',
      // send password reset token
      'sendPasswordResetToken:email'
    ],
    owner: [
      // read
      'read:firstName',
      'read:lastName',
      'read:email',
      // update
      'update:firstName',
      'update:lastName',
      'update:email',
      'update:password',
      // delete
      'delete'
    ]
  }

  return exports
}

describe('lib/guard', function () {
  it('exports a function', function () {
    expect(guard).to.be.a('function')
  })

  it('throws AssertionError if permissions is not an object', function () {
    expect(() => guard('')).to.throw(Error)
      .and.have.property('name', 'AssertionError')
  })

  it('returns a function', function () {
    expect(guard(permissions())).to.be.a('function')
  })

  describe('determineRoles', function () {
    it('constains only guest if user is guest', function () {
      const guarded = guard(permissions())(undefined, item)
      return expect(guarded.determineRoles())
        .to.eventually.deep.equal(['guest'])
    })

    it('contains authenticated, owner if user is owner', function () {
      const guarded = guard(permissions())(owner, item)
      return expect(guarded.determineRoles())
        .to.eventually.deep.equal(['authenticated', 'owner'])
    })

    it('contains authenticated if user is unrelated', function () {
      const guarded = guard(permissions())(unrelated, item)
      return expect(guarded.determineRoles())
        .to.eventually.deep.equal(['authenticated'])
    })
  })

  describe('ensureAllowed', function () {
    it('rejects if roles.owner rejects', function () {
      const permissions = {
        roles: {
          owner: () => Promise.reject('rejected')
        },
        actions: {}
      }

      const guarded = guard(permissions)(owner, '1')

      return expect(guarded.ensureAllowed('create'))
        .to.eventually.be.rejected.and.equal('rejected')
    })

    it('resolves to item if action is allowed', function () {
      const guarded = guard(permissions())(guest)
      return expect(guarded.ensureAllowed('create', item))
        .to.eventually.equal(item)
    })

    it('rejects with NotPermittedError if action is not allowed', function () {
      const guarded = guard(permissions())(guest)
      return expect(guarded.ensureAllowed('read'))
        .to.eventually.be.rejected
        .and.have.property('name', 'NotPermittedError')
    })

    it('rejects with NotPermittedError if action is not defined', function () {
      const guarded = guard(permissions())(guest)
      return expect(guarded.ensureAllowed('pee'))
        .to.eventually.be.rejected
        .and.have.property('name', 'NotPermittedError')
    })
  })

  describe('filter \'read\'', function () {
    it('resolves to an object that contains only the specified read-fields', function () {
      const guarded = guard(permissions())(owner, item)

      return guarded.filter('read', item).then(assert)

      function assert (filtered) {
        expect(Object.keys(filtered)).to.have.lengthOf(3)
        expect(filtered).to.have.property('firstName', 'Maximilian')
        expect(filtered).to.have.property('lastName', 'Schmitt')
        expect(filtered).to.have.property('email', 'maximilian.schmitt@googlemail.com')
        expect(filtered).to.not.have.property('password')
      }
    })
  })

  describe('filter \'create\'', function () {
    it('returns an object that contains only the specified create-fields', function () {
      // ['firstName', 'lastName', 'email', 'password']
      const input = {
        firstName: 'Jan',
        lastName: 'Hase',
        email: 'jan@wunderflats.com',
        password: 'ichliebemaximilianschmitt',
        salt: 'mehralsallesandere'
      }

      const guarded = guard(permissions())(guest)

      return guarded.filter('create', input).then(assert)

      function assert (filtered) {
        expect(Object.keys(filtered)).to.have.lengthOf(4)
        expect(filtered).to.have.property('firstName', 'Jan')
        expect(filtered).to.have.property('lastName', 'Hase')
        expect(filtered).to.have.property('email', 'jan@wunderflats.com')
        expect(filtered).to.have.property('password', 'ichliebemaximilianschmitt')
        expect(filtered).to.not.have.property('salt')
      }
    })
  })

  describe('filter', function () {
    it('returns an object that contains only the action-specific fields', function () {
      const input = {
        email: 'maximilian.schmitt@googlemail.com',
        password: '12345678'
      }

      const guarded = guard(permissions())(guest, item)

      return guarded.filter('sendPasswordResetToken', input).then(assert)

      function assert (filtered) {
        expect(Object.keys(filtered)).to.have.lengthOf(1)
        expect(filtered).to.have.property('email', 'maximilian.schmitt@googlemail.com')
        expect(filtered).to.not.have.property('password')
      }
    })

    it('throws NotPermittedError if action was not specified', function () {
      const input = {
        email: 'maximilian.schmitt@googlemail.com',
        password: '12345678'
      }

      const guarded = guard(permissions())(owner, item)

      return expect(filter()).to.eventually.be.rejected
        .and.have.property('name', 'NotPermittedError')

      function filter () {
        return guarded.filter('sendPasswordResetToken', input)
      }
    })
  })
})
