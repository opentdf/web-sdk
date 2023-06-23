describe('client wrapper tests', function () {

  it('decrypt error', async function () {
    return fetch('http://localhost:3000')
      .then(resp => resp.text())
      .then(function(text) {
        assert.equal('Hello, world!', text);
      });
  });

});
