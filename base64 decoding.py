import base64
import string

class BaseDecoder:
    def __init__(self):
        self.base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        self.base62_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    
    def try_base64(self, encoded):
        """Base64 디코딩 시도"""
        try:
            decoded = base64.b64decode(encoded, validate=True)
            return decoded.decode('utf-8')
        except:
            return None
    
    def try_base32(self, encoded):
        """Base32 디코딩 시도"""
        try:
            decoded = base64.b32decode(encoded)
            return decoded.decode('utf-8')
        except:
            return None
    
    def try_base58(self, encoded):
        """Base58 디코딩 시도"""
        try:
            decoded_int = 0
            for char in encoded:
                if char not in self.base58_alphabet:
                    return None
                decoded_int = decoded_int * 58 + self.base58_alphabet.index(char)
            
            # 정수를 바이트로 변환
            hex_str = hex(decoded_int)[2:]
            if len(hex_str) % 2:
                hex_str = '0' + hex_str
            
            decoded_bytes = bytes.fromhex(hex_str)
            return decoded_bytes.decode('utf-8')
        except:
            return None
    
    def try_base62(self, encoded):
        """Base62 디코딩 시도"""
        try:
            decoded_int = 0
            for char in encoded:
                if char not in self.base62_alphabet:
                    return None
                decoded_int = decoded_int * 62 + self.base62_alphabet.index(char)
            
            # 정수를 바이트로 변환
            if decoded_int == 0:
                return chr(0)
            
            hex_str = hex(decoded_int)[2:]
            if len(hex_str) % 2:
                hex_str = '0' + hex_str
            
            decoded_bytes = bytes.fromhex(hex_str)
            return decoded_bytes.decode('utf-8')
        except:
            return None
    
    def decode(self, encoded_str):
        """자동으로 인코딩 방식을 감지하고 디코딩"""
        methods = [
            ("Base64", self.try_base64),
            ("Base32", self.try_base32),
            ("Base58", self.try_base58),
            ("Base62", self.try_base62),
        ]
        
        for name, method in methods:
            result = method(encoded_str)
            if result is not None:
                print(f"✓ {name} 디코딩 성공!")
                print(f"결과: {result}")
                return result
        
        print("✗ 어떤 방식으로도 디코딩할 수 없습니다.")
        return None


def main():
    decoder = BaseDecoder()
    
    print("=" * 50)
    print("자동 Base 디코더 (Base64/32/58/62)")
    print("=" * 50)
    
    while True:
        encoded = input("\n디코딩할 문자열을 입력하세요 (종료: 'quit'): ").strip()
        
        if encoded.lower() == 'quit':
            print("프로그램을 종료합니다.")
            break
        
        if not encoded:
            print("입력이 비어있습니다.")
            continue
        
        decoder.decode(encoded)


if __name__ == "__main__":
    main()
