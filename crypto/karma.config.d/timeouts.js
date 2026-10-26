// Kotlin/JS emulates Long, so the Curve25519 tests that run thousands of scalar
// multiplications take a minute or more each, and they block the page while they run.
// Mocha's 2s test timeout would fail them, and Karma would drop the silent browser.
config.set({
    client: {
        mocha: {
            timeout: 600000,
        },
    },
    browserNoActivityTimeout: 600000,
    browserDisconnectTimeout: 600000,
    pingTimeout: 600000,
});
