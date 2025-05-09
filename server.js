process.env.GOOGLE_APPLICATION_CREDENTIALS = "C:\\Users\\Admin\\AndroidStudioProjects\\IntegrityCheck\\credentials.json";
const express = require('express');
const { GoogleAuth } = require('google-auth-library');
const jwtDecode = require('jwt-decode');
const axios = require('axios');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());
const PACKAGE_NAME = 'com.chandana.integritycheck';
const PORT = 3000;
app.post('/verify', async (req, res) => {
    try {
        const { token, nonce } = req.body;
	if (nonce.length < 16) {
        return res.status(400).json({ error: "Invalid nonce" });
    }
        if (!token || !nonce) return res.status(400).json({ error: "Token and nonce required" });
        // Step 1: Call Google API to decode the token
        const integrityData = await verifyTokenWithGoogle(token);
        // Step 2: Validate nonce
        if (integrityData.requestDetails.nonce !== nonce) {
            return res.json({ valid: false, reason: "Nonce mismatch" });
        }
        // Step 3: App integrity check
        if (integrityData.appIntegrity?.appRecognitionVerdict !== "PLAY_RECOGNIZED") {
            return res.json({ valid: false, reason: "App not recognized by Play Store" });
        }
        // Step 4: Device integrity check
        const verdicts = integrityData.deviceIntegrity?.deviceRecognitionVerdict || [];
        const isCompromised = !verdicts.includes("MEETS_DEVICE_INTEGRITY");
        res.json({ 
            valid: !isCompromised,
            details: {
                isEmulator: verdicts.includes("MEETS_VIRTUAL_INTEGRITY"),
                isRooted: isCompromised
            }
        });
    } catch (error) {
        console.error("Verification error:", error.response?.data || error.message || error);
        res.status(500).json({ error: "Integrity check failed" });
    }
});
async function verifyTokenWithGoogle(token) {
    const auth = new GoogleAuth({
        scopes: 'https://www.googleapis.com/auth/playintegrity'
    });
    const client = await auth.getClient();
    const accessToken = (await client.getAccessToken()).token;
    console.log("Access Token:", accessToken); // ✅ log access token
    try {
        const response = await axios.post(
            `https://playintegrity.googleapis.com/v1/${PACKAGE_NAME}:decodeIntegrityToken`,
            { integrity_token: token },
            { headers: { Authorization: `Bearer ${accessToken}` } }
        );
        console.log("Google Response:", response.data); // ✅ log response
        return response.data.tokenPayloadExternal;
    } catch (err) {
        console.error("Google API error:", err.response?.data || err.message || err);
        throw err;
    }
}
app.listen(3000, '0.0.0.0', () => {
  console.log('Server running on port 3000');
});
