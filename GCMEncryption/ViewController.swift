//
//  ViewController.swift
//  GCMEncryption
//
//  Created by Vijay Patidar on 11/02/21.
//

import UIKit
import CryptoKit
import CryptoTokenKit

typealias ServiceResponse = (JSON?) -> Void


class ViewController: UIViewController {
    
    @IBOutlet weak var btnCallAPI: UIButton!
    
    let password = ""
    let nonce: Data = CC.generateRandom(12)
    let salt = CC.generateRandom(16)
    let aad: Data? = nil
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
       
        
    }
    
    @IBAction func encrypt(_ sender: UIButton) {
        
        let key: Data = try! CC.KeyDerivation.PBKDF2(password, salt: salt, prf: .sha256, rounds: 65536)
        let plaintext: Data = "abcdefghijklmnop".data(using: String.Encoding.utf8)!
        
        do {
            let gcmEnc: SwiftGCM = try SwiftGCM(key: key, nonce: nonce, tagSize: SwiftGCM.tagSize128)
            
            let ciphertext: Data = try gcmEnc.encrypt(auth: aad, plaintext: plaintext)
            print("cipher text",ciphertext.base64EncodedString())
            //let ciphertext = "1e4kHQeMf+yTOhYfKfRneqrKyBW3bc8BwJ0Mw9B4yMk=".data(using: String.Encoding.utf8)!
            var cipherTextWithIvSalt = Data()
            cipherTextWithIvSalt.append(nonce)
            cipherTextWithIvSalt.append(salt)
            cipherTextWithIvSalt.append(ciphertext)
        }
        catch {
            print("Error")
        }
        
        
        
    }
    
    @IBAction func callAPI(_ sender: UIButton) {
        self.btnCallAPI.setTitle("Please wait", for: .normal)
        callAPI()
    }
    
}



extension ViewController {
    func callAPI() {
        
        let param = ["userId":"youUserId","password":"yourPassword"] as [String : Any] // This param is going to get encrypted.
        
        self.callAPI(param: param, onCompletion: {(json) in
            DispatchQueue.main.async {
                self.btnCallAPI.setTitle("Tokenmobile_API", for: .normal)
            }
            if let jsonData = json {
                print(jsonData)
            }
        })
        
    }
    
    func callAPI(param: [String : Any], onCompletion: @escaping ServiceResponse) {
        print("💡Request Body --  ",param)
        
        let request = NSMutableURLRequest(url: URL(string: "Api in which you want to send the encrypted request")!)
        
        let headers = ["Origin":"", "Content-Type" : "text/plain", "Accept" : "text/plain"]
        
        let encryptedData =  self.encryptWithGCM(paramDict:param)
        
        request.httpBody = encryptedData // Encoded request
        request.allHTTPHeaderFields = headers
        request.httpMethod = "POST"
        print("final request",request)
        apiSessionForEncodable(request: request, onCompletion:  {(json) in
            onCompletion(json)
        })
    }
    
    func apiSessionForEncodable(request : NSMutableURLRequest, onCompletion: @escaping ServiceResponse) {
        
        print("😎HTTP Method type:-", request.httpMethod)
        print("🔴RequestURL : \(request.url?.absoluteString ?? "")")
        
        
        URLSession.shared.dataTask(with: request as URLRequest) { (data, response, err) in
            
            if data == nil {
                onCompletion(nil)
            }
            
            if let resultString = String.init(data: data!, encoding: String.Encoding.utf8){
                print("response data",data?.base64EncodedString() ?? "")
                print("response string",resultString)
                
                if resultString.contains("Unauthorized.. Authentication Failure") {
                    onCompletion(nil)
                    return
                }else{
                    if let AESdecryptedData = self.dycryptWithGCM(encryptedData: resultString){
                        do {
                            let json:JSON = try JSON(data: AESdecryptedData)
                            print(json)
                            onCompletion(json)
                            return
                            
                        } catch _ {
                            onCompletion(nil)
                            return
                        }
                    }
                }
            }
            
            
        }.resume()
    }
}



extension ViewController {
  
    
    
    func encryptWithGCM(paramDict:[String:Any]) -> Data? {
        // Create AES Key from 16 bytes random generated salt and the password
        if let aesKey = try? CC.KeyDerivation.PBKDF2(password, salt: salt, prf: .sha256, rounds: 65536) {
            var theJSONText : String?
            if let theJSONData = try? JSONSerialization.data(
                withJSONObject: paramDict,
                options: []) {
                theJSONText = String(data: theJSONData,
                                     encoding: .ascii)
            } // Converting the param dict into json string
            let plaintext: Data = theJSONText!.data(using: String.Encoding.utf8)!
            
            do {
                let gcmEnc: SwiftGCM = try SwiftGCM(key: aesKey, nonce: nonce, tagSize: SwiftGCM.tagSize128)
                
                let cipherText = try gcmEnc.encrypt(auth: aad, plaintext: plaintext)
                print("cipher text",cipherText.base64EncodedString())
                
                var cipherTextWithIvSalt = Data()
                cipherTextWithIvSalt.append(nonce)
                cipherTextWithIvSalt.append(salt) // added the same salt data used for geenratng AES Key.
                cipherTextWithIvSalt.append(cipherText)
                print("cipher salt", cipherTextWithIvSalt.base64EncodedString())
                
                //base64 Encoding to pass it into the request httpBody.
                return cipherTextWithIvSalt.base64EncodedString().data(using: .utf8)
            }
            catch {
                print("Error in encrypting the data")
            }
        }
        return nil
        
        
    }
    
    func dycryptWithGCM(encryptedData: String) -> Data? {
        
        
        print("encryptedData.....",encryptedData)
        
        //Decoding the Encoded data
        if let encryptedData1 = Data(base64Encoded: encryptedData), !encryptedData1.isEmpty{
            
            print("after decoding", encryptedData1.base64EncodedString())
            
            let ivData = encryptedData1[0..<12] //deriving the iv from decrypted data(i.e. the nonce) with the help of generated nonce data length.
            print("ivStr is \(ivData.base64EncodedString())")
            
            let saltData = encryptedData1[12..<28] // deriving the salt data from the decrypted data with the help of generated salt data length.
            print("saltStr is \(saltData.base64EncodedString())")
            
            let encryptedCipherData = encryptedData1[28..<encryptedData1.count] // deriving the cipher text by removing the iv and salt from the decrypted data
            print("cipher text: ------- \(encryptedCipherData.base64EncodedString())")
            
            // Generating the AES Key with the help of password and the salt data(getting from the decrypted data)
            let aesKeyFromPassword = try? CC.KeyDerivation.PBKDF2(password, salt: saltData, prf: .sha256, rounds: 65536)
            
            do {
                let gcmDec: SwiftGCM = try SwiftGCM(key: aesKeyFromPassword!, nonce: ivData, tagSize: SwiftGCM.tagSize128)
                let result: Data = try gcmDec.decrypt(auth: aad, ciphertext: encryptedCipherData)
                print("decrpytedData",result.base64EncodedString())
                return result
            }
            catch {
                print("Error in decrypting the data")
            }
        }
        
        return nil
    }
  
    
}


extension String {
    func javaUTF8() -> Data? {
        guard let data = self.data(using: .utf8) else {
            return nil
        }
        let length = self.lengthOfBytes(using: .utf8)
        var buffer = [UInt8]()
        buffer.append(UInt8(0xff & (length >> 8)))
        buffer.append(UInt8(0xff & length))
        var outdata = Data()
        outdata.append(buffer, count: buffer.count)
        outdata.append(data)
        return outdata
    }
}


extension Data{
    func toString() -> String?
    {
        return String(data: self, encoding: .utf8)
    }
    
}
extension String{
    func aesEncrypt(key:String, iv:String) -> String? {
        if let keyData = key.data(using: String.Encoding.utf8),
           let data1 = "abcdefghijklmnop".data(using: String.Encoding.utf8),
           let cryptData = NSMutableData(length: Int((data1.count)) + kCCBlockSizeAES128) {
            
            
            let keyLength = size_t(kCCKeySizeAES128)
            let operation: CCOperation = UInt32(kCCEncrypt)
            let algoritm: CCAlgorithm = UInt32(kCCAlgorithmAES128)
            let options: UInt32 = CCOptions(kCCOptionECBMode)
            
            var numBytesEncrypted :size_t = 0
            
            let cryptStatus = CCCrypt(operation,
                                      algoritm,
                                      options,
                                      (keyData as NSData).bytes, keyLength,
                                      iv,
                                      (data1 as NSData).bytes, data1.count,
                                      cryptData.mutableBytes, cryptData.length,
                                      &numBytesEncrypted)
            
            if UInt32(cryptStatus) == UInt32(kCCSuccess) {
                cryptData.length = Int(numBytesEncrypted)
                let base64cryptString = cryptData.base64EncodedString(options: .lineLength64Characters)
                return base64cryptString
                
                
            }
            else {
                return nil
            }
        }
        return nil
    }
}

public extension String {
    
    //right is the first encountered string after left
    func between( left: String, right: String) -> String? {
        guard
            let leftRange = range(of: left), let rightRange = range(of: right, options: .backwards)
            , leftRange.upperBound <= rightRange.lowerBound
        else { return nil }
        
        let sub = self[leftRange.upperBound...]
        let closestToLeftRange = sub.range(of: right)!
        return String(sub[..<closestToLeftRange.lowerBound])
    }
    
    var length: Int {
        get {
            return self.count
        }
    }
    
    func substring(to : Int) -> String {
        let toIndex = self.index(self.startIndex, offsetBy: to)
        return String(self[...toIndex])
    }
    
    func substring(from : Int) -> String {
        let fromIndex = self.index(self.startIndex, offsetBy: from)
        return String(self[fromIndex...])
    }
    
    func substring(_ r: Range<Int>) -> String {
        let fromIndex = self.index(self.startIndex, offsetBy: r.lowerBound)
        let toIndex = self.index(self.startIndex, offsetBy: r.upperBound)
        let indexRange = Range<String.Index>(uncheckedBounds: (lower: fromIndex, upper: toIndex))
        return String(self[indexRange])
    }
    
    func character(_ at: Int) -> Character {
        return self[self.index(self.startIndex, offsetBy: at)]
    }
    
    func lastIndexOfCharacter(_ c: Character) -> Int? {
        guard let index = range(of: String(c), options: .backwards)?.lowerBound else
        { return nil }
        return distance(from: startIndex, to: index)
    }
}
