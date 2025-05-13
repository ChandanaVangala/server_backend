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

        console.log("\n--- /verify endpoint called ---");
        console.log("Received nonce:", nonce);
        console.log("Received token (first 60 chars):", token?.substring(0, 60) + "...");

        if (!token || !nonce) {
            console.log("❌ Missing token or nonce");
            return res.status(400).json({ error: "Token and nonce required" });
        }

        if (nonce.length < 16) {
            console.log("❌ Nonce too short");
            return res.status(400).json({ error: "Invalid nonce" });
        }

        const integrityData = await verifyTokenWithGoogle(token);

        console.log("✅ Decoded Integrity Data:");
        console.log(JSON.stringify(integrityData, null, 2));

        // Step 1: Validate nonce
        if (integrityData.requestDetails.nonce !== nonce) {
            console.log("❌ Nonce mismatch");
            return res.json({ valid: false, reason: "Nonce mismatch" });
        }

        // Step 2: Handle App Integrity
        const appVerdict = integrityData.appIntegrity?.appRecognitionVerdict;
        console.log("App Recognition Verdict:", appVerdict);

        switch (appVerdict) {
            case "PLAY_RECOGNIZED":
                break;
            case "UNRECOGNIZED_VERSION":
                console.log("❌ Unrecognized version - possibly sideloaded");
                return res.json({ valid: false, reason: "Unrecognized version - possibly sideloaded or debug build" });
            case "UNEVALUATED":
                console.log("❌ App integrity not evaluated");
                return res.json({ valid: false, reason: "App integrity not evaluated" });
            case "FAILED":
            default:
                console.log("❌ App integrity failed");
                return res.json({ valid: false, reason: "App integrity failed" });
        }

        // Step 3: Handle Device Integrity
        const verdicts = integrityData.deviceIntegrity?.deviceRecognitionVerdict || [];
        console.log("Device Recognition Verdicts:", verdicts);

        const hasStrong = verdicts.includes("MEETS_STRONG_INTEGRITY");
        const hasDevice = verdicts.includes("MEETS_DEVICE_INTEGRITY");
        const hasBasic = verdicts.includes("MEETS_BASIC_INTEGRITY");
        const isVirtual = verdicts.includes("MEETS_VIRTUAL_INTEGRITY");

        let integrityLevel = "UNKNOWN";
        if (hasStrong) integrityLevel = "STRONG";
        else if (hasDevice) integrityLevel = "DEVICE";
        else if (hasBasic) integrityLevel = "BASIC";

        const isCompromised = !(hasBasic || hasDevice || hasStrong);

        console.log("Final Integrity Level:", integrityLevel);
        console.log("Is Emulator:", isVirtual);
        console.log("Is Compromised:", isCompromised);

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
        console.error("❌ Verification error:");
        if (error.response?.data) {
            console.error(JSON.stringify(error.response.data, null, 2));
        } else {
            console.error(error.message || error);
        }
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

    console.log("✅ Access Token obtained:");
    console.log(accessToken);

    const response = await axios.post(
        `https://playintegrity.googleapis.com/v1/${PACKAGE_NAME}:decodeIntegrityToken`,
        { integrity_token: token },
        { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    console.log("✅ Google API Raw Response:");
    console.log(JSON.stringify(response.data, null, 2));

    return response.data.tokenPayloadExternal;
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
