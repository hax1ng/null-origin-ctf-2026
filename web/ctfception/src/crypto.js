/**
 * CTFCEPTION CRYPTOGRAPHIC RECONSTRUCTION ENGINE
 * Archive Protocol Node: PRX02-ALPHA
 * 
 * Implements client-side Web Crypto AES-256-GCM record reconstruction.
 * Note: The flag is NOT stored in plain text anywhere in source.
 * Decryption mathematically requires the SHA-256 hash of the decoded beacon phrase.
 */

(function (window) {
    'use strict';

    // Sealed archival ciphertext (AES-256-GCM with 16-byte auth tag)
    const ARCHIVE_CIPHERTEXT_HEX = "e60d10cedd2fde9039866ce40dff2ba198f28ac778638a561980cb2d054069dc8d6e47c0f8c08c67481f8ad4e94fe25de1ac70d7b78d6943fe65dfc2fc996b19d7";
    // Archival historical epoch IV (12 bytes: 1908 2509 1881 1916 1893 1897)
    const ARCHIVE_IV_HEX = "190825091881191618931897";

    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    async function reconstructBeacon(beaconKey) {
        if (!beaconKey || typeof beaconKey !== 'string') {
            throw new Error("Missing beacon key argument.");
        }

        const normalizedKey = beaconKey.trim();

        // Check if Web Crypto is supported
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error("Web Crypto API is not supported in this environment.");
        }

        try {
            const enc = new TextEncoder();
            // Derive AES key via SHA-256 digest of normalized beacon key
            const keyMaterial = await window.crypto.subtle.digest("SHA-256", enc.encode(normalizedKey));
            
            const cryptoKey = await window.crypto.subtle.importKey(
                "raw",
                keyMaterial,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );

            const iv = hexToBytes(ARCHIVE_IV_HEX);
            const ciphertext = hexToBytes(ARCHIVE_CIPHERTEXT_HEX);

            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                cryptoKey,
                ciphertext
            );

            const dec = new TextDecoder();
            const flag = dec.decode(decryptedBuffer);
            return {
                success: true,
                flag: flag,
                beacon: normalizedKey,
                timestamp: new Date().toISOString()
            };
        } catch (err) {
            return {
                success: false,
                error: "Integrity verification failed. Beacon key does not match cryptographic signature.",
                details: err.message
            };
        }
    }

    window.CTFceptionCrypto = {
        reconstructBeacon: reconstructBeacon,
        getIVHex: () => ARCHIVE_IV_HEX,
        getCiphertextHex: () => ARCHIVE_CIPHERTEXT_HEX
    };

})(window);

