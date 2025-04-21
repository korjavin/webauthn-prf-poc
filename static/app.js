// Helper utilities for WebAuthn PRF extension demo
document.addEventListener('DOMContentLoaded', function() {
    // Initialize UI elements
    const addSecretBtn = document.getElementById('addSecretBtn');
    const getPrfBtn = document.getElementById('getPrfBtn');
    const logElement = document.getElementById('log');

    // Disable getPrfBtn initially
    getPrfBtn.disabled = true;

    // Store current secret
    window.currentSecret = null;

    // Add event listeners
    if (addSecretBtn) addSecretBtn.addEventListener('click', addSecret);
    if (getPrfBtn) getPrfBtn.addEventListener('click', getPrf);

    // Helper functions for conversion and logging
    window.b64uToBuf = str => {
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    };

    window.bufToB64u = buf => {
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    };

    window.bufToHex = buf => {
        return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    };

    window.log = function(...args) {
        if (logElement) {
            logElement.textContent += args.join(' ') + '\n';
            logElement.scrollTop = logElement.scrollHeight;
        }
        console.log(...args);
    };
});

// Add a new secret
async function addSecret() {
    try {
        log('Generating a new secret...');

        // Call the API to add a new secret
        const response = await fetch('/api/secret/add', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to add secret: ${errorText}`);
        }

        // Parse the response
        const secret = await response.json();
        window.currentSecret = secret;

        // Log the secret details
        log('Secret generated successfully:');
        log('Secret ID:', secret.secretID);
        log('Salt:', secret.salt);
        log('These values are stored on the server and will be used for PRF evaluation.');

        // Enable the getPrfBtn
        document.getElementById('getPrfBtn').disabled = false;

    } catch (error) {
        log('Error adding secret:', error.message);
        console.error('Error adding secret:', error);
    }
}

// Get PRF output
async function getPrf() {
    try {
        if (!window.currentSecret) {
            log('No secret available. Please add a secret first.');
            return;
        }

        log('Getting PRF output for secret ID:', window.currentSecret.secretID);

        // Step 1: Get assertion options with PRF extension
        log('Step 1: Requesting assertion options with PRF extension...');
        const optionsResponse = await fetch('/api/prf/assertionOptions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                secretID: window.currentSecret.secretID
            })
        });

        if (!optionsResponse.ok) {
            const errorText = await optionsResponse.text();
            throw new Error(`Failed to get assertion options: ${errorText}`);
        }

        // Parse the options
        const options = await optionsResponse.json();
        log('Received assertion options:');
        log(JSON.stringify(options, null, 2));

        // Step 2: Convert base64url strings to ArrayBuffers where needed
        log('Step 2: Converting options for WebAuthn API...');

        if (options.publicKey.challenge) {
            options.publicKey.challenge = b64uToBuf(options.publicKey.challenge);
        }

        if (options.publicKey.allowCredentials) {
            options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(cred => {
                return {
                    ...cred,
                    id: b64uToBuf(cred.id)
                };
            });
        }

        // Convert PRF extension values to ArrayBuffers
        if (options.publicKey.extensions && options.publicKey.extensions.prf && options.publicKey.extensions.prf.eval && options.publicKey.extensions.prf.eval.first) {
            options.publicKey.extensions.prf.eval.first = b64uToBuf(options.publicKey.extensions.prf.eval.first);
        }

        log('Options prepared for WebAuthn API');

        // Step 3: Call navigator.credentials.get()
        log('Step 3: Calling navigator.credentials.get() with PRF extension...');
        log('This will prompt the authenticator to evaluate the PRF with the provided salt.');

        const credential = await navigator.credentials.get({
            publicKey: options.publicKey
        });

        log('Authenticator response received!');

        // Step 4: Extract PRF result
        log('Step 4: Extracting PRF result from authenticator response...');

        const clientExtResults = credential.getClientExtensionResults();
        log('Client extension results:', JSON.stringify(clientExtResults, null, 2));

        if (!clientExtResults.prf || !clientExtResults.prf.results || !clientExtResults.prf.results.first) {
            throw new Error('PRF extension result not found in authenticator response');
        }

        const prfResult = clientExtResults.prf.results.first;
        log('PRF output (hex):', bufToHex(prfResult));
        log('PRF output (base64):', btoa(String.fromCharCode(...new Uint8Array(prfResult))));
        log('This 32-byte value is deterministic for this credential and salt combination.');

        // Step 5: Send PRF result to server
        log('Step 5: Sending PRF result to server...');

        const storeResponse = await fetch('/api/secret/storeResult', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                secretID: window.currentSecret.secretID,
                prfOutput: btoa(String.fromCharCode(...new Uint8Array(prfResult)))
            })
        });

        if (!storeResponse.ok) {
            const errorText = await storeResponse.text();
            throw new Error(`Failed to store PRF result: ${errorText}`);
        }

        const storeResult = await storeResponse.json();
        log('Server response:', JSON.stringify(storeResult, null, 2));
        log('PRF output stored successfully on the server.');
        log('');
        log('Try clicking "Get PRF Output" again to verify that the same output is produced.');

    } catch (error) {
        log('Error getting PRF output:', error.message);
        console.error('Error getting PRF output:', error);
    }
}
