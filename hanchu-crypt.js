        // AES constants — must match Swift AESHelper exactly
        const BASE_KEY = 'gxkj@2099@1914zy';
        const BASE_IV  = '9z64Qr8mZH7Pg8d1';

        let dynamicKey = null
    
        // AES Encryption Helper — matches Swift AESHelper exactly (AES-128-CFB8)
        const AESHelper = {
            // Convert Uint8Array → CryptoJS WordArray (big-endian)
            _toWordArray(bytes) {
                const words = [];
                for (let i = 0; i < bytes.length; i += 4) {
                    words.push(
                        ((bytes[i]   || 0) << 24) |
                        ((bytes[i+1] || 0) << 16) |
                        ((bytes[i+2] || 0) <<  8) |
                        ((bytes[i+3] || 0))
                    );
                }
                return CryptoJS.lib.WordArray.create(words, bytes.length);
            },

            // Encrypt one 16-byte block with AES-128-ECB, return first 16 bytes
            _ecbBlock(keyBytes, blockBytes) {
                const key = this._toWordArray(keyBytes);
                const blk = this._toWordArray(blockBytes);
                const enc = CryptoJS.AES.encrypt(blk, key, {
                    mode: CryptoJS.mode.ECB,
                    padding: CryptoJS.pad.Pkcs7   // input is 16 bytes; PKCS7 adds a padding block
                });
                // ECB encrypts blocks independently — first 16 bytes = encrypt(blockBytes)
                const w = enc.ciphertext.words;
                const out = new Uint8Array(16);
                for (let i = 0; i < 4; i++) {
                    out[i*4]   = (w[i] >>> 24) & 0xFF;
                    out[i*4+1] = (w[i] >>> 16) & 0xFF;
                    out[i*4+2] = (w[i] >>>  8) & 0xFF;
                    out[i*4+3] =  w[i]          & 0xFF;
                }
                return out;
            },

            init() {
                // Generate a random 6-character alphanumeric string
                const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                randomFix = '';
                for (let i = 0; i < 6; i++) {
                    randomFix += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                log(`🔑 Generated random fix: ${randomFix}`);

                // Packet: [0x05][6 UTF-8 bytes of randomFix] = 7 bytes total
                const fixBytes = new TextEncoder().encode(randomFix); // 6 bytes (all ASCII)
                const randomFixPacket = new Uint8Array(7);
                randomFixPacket[0] = 0x05;
                randomFixPacket.set(fixBytes, 1);

                // Derive dynamic key from the random fix and store globally
                dynamicKey = AESHelper.generateDynamicKey(randomFix);
                
                return randomFixPacket
            },

            // Generate dynamic key
            // offset = ASCII(lastChar) % 10; replace BASE_KEY[offset..offset+5] with randomFix
            generateDynamicKey(fix) {
                if (fix.length !== 6) {
                    console.error('randomFix must be exactly 6 characters');
                    return BASE_KEY;
                }
                const offset = fix.charCodeAt(5) % 10;
                const keyArr = BASE_KEY.split('');
                for (let i = 0; i < 6; i++) {
                    if (offset + i < keyArr.length) keyArr[offset + i] = fix[i];
                }
                const dynKey = keyArr.join('');
                log(`🔑 Dynamic key generated (offset=${offset})`);
                return dynKey;
            },

            // Internal CFB8 core — isDecrypt controls feedback byte
            _cfb8(data, key) {
                const enc   = new TextEncoder();
                const keyB  = enc.encode(key).slice(0, 16);
                let   iv    = enc.encode(BASE_IV).slice(0, 16);
                const input = (data instanceof Uint8Array) ? data : new Uint8Array(data);
                const output = new Uint8Array(input.length);

                for (let i = 0; i < input.length; i++) {
                    const ks      = this._ecbBlock(keyB, iv);
                    const encByte = ks[0] ^ input[i];
                    output[i]     = encByte;
                    // CFB8 feedback: shift IV left 1 byte, append ciphertext byte
                    const newIv = new Uint8Array(16);
                    newIv.set(iv.subarray(1));
                    newIv[15] = encByte;
                    iv = newIv;
                }
                return output;
            },

            // Encrypt with current dynamic key (CFB8)
            encrypt(data) {
                if (!dynamicKey) { log('❌ No dynamic key!', 'error'); return null; }
                return this._cfb8(data, dynamicKey);
            },

            // Decrypt with current dynamic key (CFB8)
            // For CFB8, decrypt = encrypt the IV block then XOR, but feedback uses ciphertext byte
            decrypt(encryptedData) {
                if (!dynamicKey) { log('❌ No dynamic key!', 'error'); return null; }
                try {
                    const enc   = new TextEncoder();
                    const keyB  = enc.encode(dynamicKey).slice(0, 16);
                    let   iv    = enc.encode(BASE_IV).slice(0, 16);
                    const input = (encryptedData instanceof Uint8Array) ? encryptedData : new Uint8Array(encryptedData);
                    const output = new Uint8Array(input.length);

                    for (let i = 0; i < input.length; i++) {
                        const ks      = this._ecbBlock(keyB, iv);
                        output[i]     = ks[0] ^ input[i];
                        // CFB8 decrypt feedback: shift IV left, append ciphertext byte (not plaintext)
                        const newIv = new Uint8Array(16);
                        newIv.set(iv.subarray(1));
                        newIv[15] = input[i];
                        iv = newIv;
                    }
                    return output;
                } catch (error) {
                    log(`❌ Decryption error: ${error.message}`, 'error');
                    return null;
                }
            }
        };
