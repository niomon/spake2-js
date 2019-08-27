/**
 * ...
 *
 * @param {*} identityA ...
 * @param {*} identityB ...
 * @param {*} password ...
 * @param {*} suite ...
 * @returns {*} ...
 */
function startA (identityA, identityB, password, suite) {
  return state()
}

/**
 * ...
 *
 * @param {*} identityA ...
 * @param {*} identityB ...
 * @param {*} password ...
 * @param {*} suite ...
 * @returns {*} ...
 */
function startB (identityA, identityB, password, suite) {
  return state()
}

/**
 * ...
 *
 * @returns {*} ...
 */
function state () {
  return {
    getMessage () {},
    finish () {
      return sharedSecret()
    }
  }
}

/**
 * ...
 *
 * @returns {*} ...
 */
function sharedSecret () {
  return {
    getConfirmation () {},
    verify () {},
    toBuffer () {}
  }
}

exports.startA = startA
exports.startB = startB
