const express = require('express');
const { GoogleAuth } = require('google-auth-library');
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

        const integrityData = await verifyTokenWithGoogle(token);

        // Step 1: Validate nonce
        if (integrityData.requestDetails.nonce !== nonce) {
            return res.json({ valid: false, reason: "Nonce mismatch" });
        }

        // Step 2: Handle App Integrity
        const appVerdict = integrityData.appIntegrity?.appRecognitionVerdict;

        switch (appVerdict) {
            case "PLAY_RECOGNIZED":
                // Trusted app from Play Store
                break;
            case "UNRECOGNIZED_VERSION":
                return res.json({
                    valid: false,
                    reason: "Unrecognized version - possibly sideloaded or debug build"
                });
            case "UNEVALUATED":
                return res.json({
                    valid: false,
                    reason: "App integrity not evaluated"
                });
            case "FAILED":
            default:
                return res.json({
                    valid: false,
                    reason: "App integrity failed"
                });
        }

        // Step 3: Handle Device Integrity
        const verdicts = integrityData.deviceIntegrity?.deviceRecognitionVerdict || [];

        const hasStrong = verdicts.includes("MEETS_STRONG_INTEGRITY");
        const hasDevice = verdicts.includes("MEETS_DEVICE_INTEGRITY");
        const hasBasic = verdicts.includes("MEETS_BASIC_INTEGRITY");
        const isVirtual = verdicts.includes("MEETS_VIRTUAL_INTEGRITY");

        let integrityLevel = "UNKNOWN";
        if (hasStrong) integrityLevel = "STRONG";
        else if (hasDevice) integrityLevel = "DEVICE";
        else if (hasBasic) integrityLevel = "BASIC";

        const isCompromised = !(hasBasic || hasDevice || hasStrong);

        res.json({
            valid: !isCompromised,
            integrityLevel,
            details: {
                appRecognitionVerdict: appVerdict,
                deviceRecognitionVerdict: verdicts,
                isEmulator: isVirtual,
                isRootedOrTampered: isCompromised
            }
        });

    } catch (error) {
        console.error("Verification error:", error.response?.data || error.message || error);
        res.status(500).json({ error: "Integrity check failed" });
    }
});

async function verifyTokenWithGoogle(token) {
    const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS);
    const auth = new GoogleAuth({
        credentials: credentials,
        scopes: 'https://www.googleapis.com/auth/playintegrity'
    });

    const client = await auth.getClient();
    const accessToken = (await client.getAccessToken()).token;

    const response = await axios.post(
        `https://playintegrity.googleapis.com/v1/${PACKAGE_NAME}:decodeIntegrityToken`,
        { integrity_token: token },
        { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    return response.data.tokenPayloadExternal;
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
