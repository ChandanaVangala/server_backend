const express = require('express');
const { GoogleAuth } = require('google-auth-library');
const jwtDecode = require('jwt-decode');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const PACKAGE_NAME = 'com.chandana.integritycheck';
const PORT = process.env.PORT || 3000;

app.post('/verify', async (req, res) => {
    try {
        const { token, nonce } = req.body;

        if (!token || !nonce) {
            return res.status(400).json({ error: "Token and nonce required" });
        }

        if (nonce.length < 16) {
            return res.status(400).json({ error: "Invalid nonce" });
        }

        // Step 1: Call Google API to decode the token
        const integrityData = await verifyTokenWithGoogle(token);

        // Step 2: Validate nonce
        if (integrityData.requestDetails?.nonce !== nonce) {
            return res.json({ 
                valid: false, 
                reason: "Nonce mismatch", 
                details: null 
            });
        }

        // Step 3: App integrity check
        const appVerdict = integrityData.appIntegrity?.appRecognitionVerdict;
        if (appVerdict !== "PLAY_RECOGNIZED") {
            return res.json({ 
                valid: false, 
                reason: "App not recognized by Play Store",
                details: {
                    appRecognitionVerdict: appVerdict
                }
            });
        }

        // Step 4: Device integrity check
        const verdicts = integrityData.deviceIntegrity?.deviceRecognitionVerdict || [];

        const details = {
            appRecognitionVerdict: appVerdict,
            deviceRecognitionVerdict: verdicts,
            meetsBasicIntegrity: verdicts.includes("MEETS_BASIC_INTEGRITY"),
            meetsDeviceIntegrity: verdicts.includes("MEETS_DEVICE_INTEGRITY"),
            meetsStrongIntegrity: verdicts.includes("MEETS_STRONG_INTEGRITY"),
            isEmulator: verdicts.includes("MEETS_VIRTUAL_INTEGRITY"),
            isRooted: verdicts.includes("UNKNOWN") || verdicts.includes("FAILED") || verdicts.includes("UNKNOWN_OR_ROOTED"),
            isCompromised: !verdicts.includes("MEETS_DEVICE_INTEGRITY")
        };

        // Final validity based on device integrity
        const valid = verdicts.includes("MEETS_DEVICE_INTEGRITY");

        res.json({ 
            valid,
            reason: valid ? "All checks passed" : "Device integrity failed",
            details
        });
    } catch (error) {
        console.error("Verification error:", error.response?.data || error.message || error);
        res.status(500).json({ 
            error: "Integrity check failed",
            details: null
        });
    }
});

async function verifyTokenWithGoogle(token) {
    const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS); // From Render env
    const auth = new GoogleAuth({
        credentials,
        scopes: 'https://www.googleapis.com/auth/playintegrity'
    });

    const client = await auth.getClient();
    const accessToken = (await client.getAccessToken()).token;
    console.log("Access Token:", accessToken);

    const response = await axios.post(
        `https://playintegrity.googleapis.com/v1/${PACKAGE_NAME}:decodeIntegrityToken`,
        { integrity_token: token },
        { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    console.log("Google Response:", response.data);
    return response.data.tokenPayloadExternal;
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
