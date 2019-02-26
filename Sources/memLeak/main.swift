import OpenSSL
import Foundation

let rsaPubKey = 
"""
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0
FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/
3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB
-----END PUBLIC KEY-----
"""
let rsaPrivKey = 
"""
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp
wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5
1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh
3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2
pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX
GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il
AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF
L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k
X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl
U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ
37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=
-----END RSA PRIVATE KEY-----
"""

class PublicKey {
    let nativeKey: OpaquePointer?
    deinit {
        EVP_PKEY_free(.make(optional: nativeKey))
    }
    public init(data: Data) {
        
        // Create a memory BIO...
        let bio = BIO_new(BIO_s_mem())
        
        defer {
            BIO_free(bio)
        }
        
        // Create a BIO object with the key data...
        data.withUnsafeBytes() { (buffer: UnsafePointer<UInt8>) in
            BIO_write(bio, buffer, Int32(data.count))
            // The below is equivalent of BIO_flush...
            BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nil)
        }
        
        var evp_key = EVP_PKEY_new()        
        PEM_read_bio_PUBKEY(bio, &evp_key, nil, nil)
        self.nativeKey = .make(optional: evp_key)
    }
    
    public func verify(data: Data, signature: Data) -> Bool {
        let md_ctx = EVP_MD_CTX_new_wrapper()
        defer { EVP_MD_CTX_free_wrapper(md_ctx) }
        let (md, padding) = (EVP_sha256(), RSA_PKCS1_PADDING)
        
        // Provide a pkey_ctx to EVP_DigestSignInit so that the EVP_PKEY_CTX of the signing operation
        // is written to it, to allow alternative signing options to be set
        var pkey_ctx = EVP_PKEY_CTX_new(.make(optional: self.nativeKey), nil)
        EVP_DigestVerifyInit(md_ctx, &pkey_ctx, .make(optional: md), nil, .make(optional: self.nativeKey))
        
        // Now that EVP_DigestVerifyInit has initialized pkey_ctx, set the padding option
        EVP_PKEY_CTX_ctrl(pkey_ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, padding, nil)
        
        let _ = data.withUnsafeBytes({ (message: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DigestUpdate(md_ctx, message, data.count)
        })
        
        // Unlike other return values above, this return indicates if signature verifies or not
        let rc = signature.withUnsafeBytes({ (sig: UnsafePointer<UInt8>) -> Int32 in
            // Wrapper for OpenSSL EVP_DigestVerifyFinal function defined in
            // IBM-Swift/OpenSSL/shim.h, to provide compatibility with OpenSSL
            // 1.0.1 and 1.0.2 on Ubuntu 14.04 and 16.04, respectively.
            return SSL_EVP_digestVerifyFinal_wrapper(md_ctx, sig, signature.count)
        })
        
        return rc == 1
    }
}

class PrivateKey {
    let nativeKey: OpaquePointer?
    deinit {
        EVP_PKEY_free(.make(optional: nativeKey))
    }
    public init(data: Data) {
        
        // Create a memory BIO...
        let bio = BIO_new(BIO_s_mem())
        
        defer {
            BIO_free(bio)
        }
        
        // Create a BIO object with the key data...
        data.withUnsafeBytes() { (buffer: UnsafePointer<UInt8>) in
            BIO_write(bio, buffer, Int32(data.count))
            // The below is equivalent of BIO_flush...
            BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nil)
        }
        
        var evp_key = EVP_PKEY_new()        
        PEM_read_bio_PrivateKey(bio, &evp_key, nil, nil)
        self.nativeKey = .make(optional: evp_key)
    }
    
    public func sign(data: Data) -> Data? {
        let md_ctx = EVP_MD_CTX_new_wrapper()
        defer { EVP_MD_CTX_free_wrapper(md_ctx) }
        let (md, padding) = (EVP_sha256(), RSA_PKCS1_PADDING)
        
        // Provide a pkey_ctx to EVP_DigestSignInit so that the EVP_PKEY_CTX of the signing operation
        // is written to it, to allow alternative signing options to be set
        var pkey_ctx = EVP_PKEY_CTX_new(.make(optional: self.nativeKey), nil)
        EVP_DigestSignInit(md_ctx, &pkey_ctx, .make(optional: md), nil, .make(optional: self.nativeKey))
        
        // Now that Init has initialized pkey_ctx, set the padding option
        EVP_PKEY_CTX_ctrl(pkey_ctx, EVP_PKEY_RSA, -1, EVP_PKEY_CTRL_RSA_PADDING, padding, nil)
        
        // Convert Data to UnsafeRawPointer!
        _ = data.withUnsafeBytes({ (message: UnsafePointer<UInt8>) -> Int32 in
            return EVP_DigestUpdate(md_ctx, message, data.count)
        })
        
        // Determine the size of the actual signature
        var sig_len: Int = 0
        EVP_DigestSignFinal(md_ctx, nil, &sig_len)
        let sig = UnsafeMutablePointer<UInt8>.allocate(capacity: sig_len)
        
        defer {
            #if swift(>=4.1)
            sig.deallocate()
            #else
            sig.deallocate(capacity: sig_len)
            #endif
        }
        
        EVP_DigestSignFinal(md_ctx, sig, &sig_len)
        return Data(bytes: sig, count: sig_len)
    } 
}

    
for _ in 0 ..< 10000 {
    let privateKey = PrivateKey(data: rsaPrivKey.data(using: .utf8)!)
    let plaintext = "Hello".data(using: .utf8)!
    let signature = privateKey.sign(data: plaintext)
    let publicKey = PublicKey(data: rsaPubKey.data(using: .utf8)!)
    let verified = publicKey.verify(data: plaintext, signature: signature!)
}
