import * as entry from '../src/wafflecrypt'
import * as browser from '../src/browser'

test('entry is/mirrors browser', () => {
  Object.keys(entry).forEach((method) => {
    expect(entry[method]).toBe(browser[method])
  })
})
