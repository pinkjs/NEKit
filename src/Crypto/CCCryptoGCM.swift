import Foundation
import CommonCrypto

open class CCCryptoGCM {

    let cryptor: CCCryptorRef

    public init(operation: CryptoOperation, initialVector: Data?, key: Data) {
        let cryptor = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)
        _ = key.withUnsafeBytes { k in
            if let initialVector = initialVector {
                _ = initialVector.withUnsafeBytes { iv in
                    CCCryptorCreateWithMode(operation.toCCOperation(),CCMode(kCCModeGCM), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding), iv.baseAddress!, k.baseAddress!, key.count, nil, 0, 0, 0, cryptor)
                }
            } else {
                CCCryptorCreateWithMode(operation.toCCOperation(), CCMode(kCCModeGCM), CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding), nil, k.baseAddress!, key.count, nil, 0, 0, 0, cryptor)
            }
        }
        self.cryptor = cryptor.pointee!
    }

//    open func update( _ data: inout Data) {
//        let count = data.count
//        _ = data.withUnsafeMutableBytes {
//            CCCryptorUpdate(cryptor, $0.baseAddress!, count, $0.baseAddress!, count, nil)
//        }
//    }
    
    open func encrypto(_ data: inout Data) {
        let count = data.count
        _ = data.withUnsafeMutableBytes {
            CCCryptorGCMEncrypt(cryptor, $0.baseAddress!, count, $0.baseAddress!)
        }
    }
    
    open func decrypto(_ data: inout Data) {
        let count = data.count
            _ = data.withUnsafeMutableBytes {
            CCCryptorGCMDecrypt(cryptor, $0.baseAddress!, count, $0.baseAddress!)
        }
    }

    deinit {
        CCCryptorRelease(cryptor)
    }

}
