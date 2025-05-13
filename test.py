from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import json

# 📌 Şifreli .pier dosyasının içeriği (hex string olarak)
hex_data = b"""0afed6992189fc1c5aff68e8768ffc6e69ffc49b3e30f817172e2cef53e3703381519fb0989b1e71f2fa8f8a5a4b7a2d1285b25f16e3768f6537fba59ed145ff94b9ef1cc796afcd5cc32571ae7b585a20b5f1b11dcde0df7ae4e377044e61025f2e27ec6ce0263451f2a113d4b467899b7da2e11383868c012867a64c2db26bfc5c91884ae2a9664c5dddd127e0c8be02d1a7a2f75b2f0c68f8ded28166ec9fb753c2f76f6ce20b500662b1c54ad2a24be920a920f06747cb3bb8e5aef54183f25b92bc7040dc1b4ad1f6a3bd22352a29e92b69a0d26c89621e046f9b96812a5ec1c080e346dc56a68d59e8885c4e71965e4b2c3ac132a7f28f30e0433f20a18f961450ae153d41755099677f70a43f171e0a96f797aa501125d7acb2d2f003cd2900578d9166cb8c113c7bf79272e2ab1a41df19bc39993182489f201a8557372e7d7632dc9a91fb47b967125b3228441a83d9838ad6eb3c4fd808c2cdf0e51e3fa1c51f367c9044695ba3f7a757de133ee39de2f03fa16fbc8363a0f45609d886c5eebc178820e0041fa24c4103c281009ec65cd5e56fe4d714256a7d2ef6d2e096d7603d52049a715249ba0cf6d32e1b9dc6ec03694b713dc4ad13d739049bb680d43e306cc707c443bcb652f3ab239b2337a8db4356d0c8bb9f3d44e1ba317de35dfd0e8df2b25d55c9d7a17c6c735cb82171e109365e303db79ac99fba4a9229858d047669eb719ba556fe0d0718689fa07d249e2b8d2791e85130cfcb22e5742c8987615327a84060418588f78eb0c523700f07fd5491fde8ed3498d9a62e6cbc06fa00240b9c0e755929bd0ed6c2a178e0d4bf5cd17e1c23760735a08352e6bec9fb5109e3ee89a5da8a388e8599b0afef4fa9ef113eddfb103308b6382c0b01128305f0658b3c4e814cc0cae9468c061fb4f2a737ba3f02ab5527d6f0ab1e0e33bffa0694673c073bfb063fb03f4812d73404b0075153f9fff6ae986da134b6bd497de5d22337af14670dd003b2004e2b338b4c22e0eb2b68e77da0988c0a058ee0e83c457f027c4c99b451624d200550afaa43d7de0f990d2753963b7b43df65cc3ca05135ec79f52eb58039bdf468d23e522f8480dfc46daee6f1fb7020d4802c2c42e00ae9b2f104d5b122cd69f67bad36c0e3f0d45d43bf1911298ae4195bfa4d3fd712aa87a7d4bf6f6bc4d2679af65b377d40262422334ad8c275e5da27b7ddae9f6c914d04453a3db3b5afb4b7bf65702dc6df06f2e2cb87087634142a0fc05ecd77f253fdb8f6fc42041b738402d3555fa20f0b5cd6d49d97ad9c26771786efb163d87df89f35e37640a0efcd4aa89979e8f67e15b1545261f0e25c46dd82a65a552dc9abf42719d6a936d0b17ef843ba5ddce1caaf64b0364802c30ca24e62d208ba7be73d13feec6f4f59ab59643d8e116f336fda79d306557bf2ed1d9be49e7f75858ab025978c77c4fa3ddedb1bba630f53770a59f309d48c5b21321b7a0a77e427ae80bfc4d8b4981317475cc869cc4e2d156bd6ac36f0966dfb7eeb2f196eb9f6003ca8630cc5b4438d87efbf255e9971aeb7013feebdb0e414189de3b1eb0ce6e2523a910940f436f693b29226ce2c1784449b333ace2a5783b23b4e676293bbb2233d555aa355dc96bb51af6c63fe788e348c2987bfeb5c7e6db9163f6a90fe736f80cc148130831ba45a3e2acbd08b98848bc8b7f435af11761600c22a737611ff3c23d0af8152d7adc047eed9fa066fb54a016beac6b16455979fd4dc67407e7b9d30e10f6d17a2bce9e17b1ae802619854bad312597789b19d69fbd1594748403bf175448a6a09f47142f4773ca6e4cf35e07f5d11ef45e9b4e4df81fec145c9b10582ecc2c82c947cfb0310dfd2d4576ae8765a66b17f5249f46d9df5907e12ac894895d31ccff3d491023530791c98e4b79bbb8859958b25367b4ba09b1f9d18cc59e4b015ceacab1634d50b719899dd3558177c9c35bf5e14ee283c6aff898ab2e9ae50f6d515f6b0c800e4848874659fd0c4b6a52d86417bb33aafc9606655a8a7f01f571fe1644f40d9ea618b91f75a8a2f1b97a1670f2d46fb76d12bb109b13724d1aabb86c33ae2a229cc9021d0fc4e918400a26f9b7b926280b33600cb2350aa664f797f149b59b86d9e0b1722cc4c3946fe9d122c48c13b2d79fa7b7f65fed128e27c01b45ab52baf8f79005009653e8e2fabc9c4c980ee15ecb6164ad5b611f11a0cf23169db432034ef7e63333ce39df03ac17e0797f238ceeff962c573a88179454b9019678dfc20c218e39353bd35d32dcfe5531bdfae29aecf39f6a4cce3ff2994bbcfd125e586d8933c4778bf70e91b7271d4e6dccf1a6edbf8a87da1291470ff4d489710e79146ea92360dca17a46154578cd96c60f38905d59477e4291dcba3505e8c631462742da435cc204283257fe002c31ec3e49d36a55e1f40887eba68eb1fdc83f3aec566ed5d33fba2299314f1e73f62dd157c0c6cd6421d7ad83b428f71dd0bd132ff093f1f46a8b420e6163869bec70c14bb84b6713d9e507f2bb012ac173547bda77b656165bdbfe8f6f696a048f07ad3844fa1ef86a3172a8425da0f8d8ea37198a82efe672c96c5037ccde238c18dd4ff66b50693b31cd8c678171fad045edd93d17a085387d03727a9a3917b74f66979e8c4cdb01fbba1fc28d45853f03405d75bba54d92ba46235e165bc110d994d2e0585641deeaefec4e2df45a15f7488c97eb2a1e888627103c8a02187a8084bddeb3a6f9ade28f9c5bbb24cbd34fc590b7a206decad8fdf2116d45cb0205dbd570ac436dc04a2e7eaf3554943319856acfaf4236ca3cb95545cebc28f2ee3416345b7a31471cce37edfe5237238066a430c1302413d1e122c6df052f3ac1d04469e4b974f060b1d212f1912efc79e9acb91ea13ba4e38462074acba8787967fbdb8ac0687b4c570f3adcf5306f2047057d5bcec00c2646ac3a1bc3b1bc31b1205813c2827942f69a9afcb0e7ff921fbb284e18c81bd1914a720843d8ccfcc4214548d276a1b1ce9073a895a5723b91544e9472bab2b59c790bb58d14fdd9478bd8edb785e4ef06a05dce6b6a382f2ea92bf4368eb9f52a1241ce2b06542f9b4c2899ad38c1725a09d0a18b98bd2c13379309e373b9280825548ed0050c70e7e05379431c32f7d652b40f63c37f5ad6874ee5c67"""

# AES anahtarı
aes_key = bytes.fromhex("c167ff3136e6a497d7eea9f430080ba9")

print("🔐 Şifreli veri uzunluğu:", len(hex_data))

try:
    # Veriyi binary'e çevir
    encrypted_data = bytes.fromhex(hex_data)
    print("📦 Binary veri uzunluğu:", len(encrypted_data))

    # İlk 16 bayt IV
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    print("🧩 IV:", iv.hex())
    print("🧩 Şifreli veri:", ciphertext[:32].hex(), "...")

    # Şifre çözücü oluştur
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    pri
    # Padding temizle
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # JSON çözümle
    decoded_json = plaintext.decode("utf-8")
    print("\n✅ JSON başarıyla çözüldü:")
    print(json.dumps(json.loads(decoded_json), indent=2, ensure_ascii=False))

except Exception as e:
    print("❌ Hata oluştu:", str(e))

# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.backends import default_backend
# import json

# filepath = "F:/modem-10-config-20250512175929.pier"
# aes_key = bytes.fromhex("c167ff3136e6a497d7eea9f430080ba9")
# # bytes.fromhex("c167ff3136e6a497d7eea9f430080ba9".encode().hex())

# try:
#     print(f"\n AES şifrelenmiş dosya okunuyor: {filepath}")
    
#     with open(filepath, "rb") as f:
#         hex_string = f.read().decode("ascii").strip()  
#         raw_data = bytes.fromhex(hex_string)

#     print(f"📦 Binary veri uzunluğu: {len(raw_data)} byte")

#     iv = raw_data[:16]
#     ciphertext = raw_data[16:]

#     print(f"IV: {iv.hex()}")
#     print(f"Ciphertext ilk 16 byte: {ciphertext[:16].hex()}")

#     cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
#     decryptor = cipher.decryptor()
#     padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

#     print(f"Padding'li düz metin uzunluğu: {len(padded_plaintext)} byte")

#     unpadder = padding.PKCS7(128).unpadder()
#     plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

#     print(f"Padding kaldırıldı. Düz metin uzunluğu: {len(plaintext)} byte")
#     decoded_json = plaintext.decode("utf-8")
#     parsed = json.loads(decoded_json)
#     print("JSON başarıyla çözüldü.")
#     print(json.dumps(parsed, indent=2))

# except Exception as e:
#     print(f"Hata oluştu: {e}")

