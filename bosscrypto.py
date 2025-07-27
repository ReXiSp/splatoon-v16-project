import os
import hashlib
import hmac
from dataclasses import dataclass
from typing import Union, Optional

# cryptographyライブラリが必要です: pip install cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac as crypto_hmac, hashes

# --- 型定義と定数 ---

@dataclass
class WUPBOSSInfo:
    """復号されたWii UのBOSSコンテナの情報を保持します。"""
    hash_type: int
    iv: bytes
    hmac: bytes
    content: bytes

BOSS_WUP_VER = 0x20001

# これらは実際のAESキーとHMACキーのMD5ハッシュであり、キーの検証に使用されます。
# 実際のキーはソースコードには含まれていません。
BOSS_AES_KEY_HASH = bytes.fromhex('5202ce5099232c3d365e28379790a919')
BOSS_HMAC_KEY_HASH = bytes.fromhex('b4482fef177b0100090ce0dbeb8ce977')

# --- ヘルパー関数 ---

def _md5(data: str) -> bytes:
    """UTF-8エンコードされた文字列のMD5ハッシュを計算します。"""
    return hashlib.md5(data.encode('utf-8')).digest()

def _get_data_from_path_or_buffer(path_or_buffer: Union[str, bytes]) -> bytes:
    """ファイルパスからデータを読み込むか、bytesオブジェクトをそのまま返します。"""
    if isinstance(path_or_buffer, str):
        with open(path_or_buffer, 'rb') as f:
            return f.read()
    elif isinstance(path_or_buffer, bytes):
        return path_or_buffer
    else:
        raise TypeError("入力はファイルパス(str)またはbytesである必要があります。")

def _verify_keys(aes_key: str, hmac_key: str) -> None:
    """提供されたキーが既知のMD5ハッシュと一致するか検証します。"""
    if BOSS_AES_KEY_HASH != _md5(aes_key):
        raise ValueError('無効なBOSS AESキーです')

    if BOSS_HMAC_KEY_HASH != _md5(hmac_key):
        raise ValueError('無効なBOSS HMACキーです')

# --- メイン関数 ---

def decrypt_wiiu(path_or_buffer: Union[str, bytes], aes_key: str, hmac_key: str) -> WUPBOSSInfo:
    """
    Wii UのBOSSコンテナファイルを復号します。

    Args:
        path_or_buffer: BOSSファイルのパス、またはその内容を含むbytesオブジェクト。
        aes_key: BOSSのAESキー（文字列）。
        hmac_key: BOSSのHMACキー（文字列）。

    Returns:
        復号されたデータとメタデータを含むWUPBOSSInfoオブジェクト。
    """
    _verify_keys(aes_key, hmac_key)

    data = _get_data_from_path_or_buffer(path_or_buffer)

    # ヘッダーからメタデータを読み込み
    hash_type = int.from_bytes(data[0xA:0xC], 'big')

    if hash_type != 2:
        raise ValueError('不明なハッシュタイプです')

    # AES-CTRモード用の16バイトのIVを構築
    iv_part = data[0xC:0x18]  # ヘッダーから12バイト
    counter = b'\x00\x00\x00\x01' # CTRモードの標準的な開始カウンター
    iv_full = iv_part + counter

    # コンテンツを復号
    aes_key_bytes = aes_key.encode('utf-8')
    cipher = Cipher(algorithms.AES(aes_key_bytes), modes.CTR(iv_full))
    decryptor = cipher.decryptor()
    
    encrypted_content = data[0x20:]
    decrypted = decryptor.update(encrypted_content) + decryptor.finalize()

    # 復号されたペイロードからHMACとコンテンツを抽出
    hmac_from_file = decrypted[:0x20]
    content = decrypted[0x20:]

    # HMACを検証
    hmac_key_bytes = hmac_key.encode('utf-8')
    h = crypto_hmac.HMAC(hmac_key_bytes, hashes.SHA256())
    h.update(content)
    calculated_hmac = h.finalize()

    # タイミング攻撃対策としてhmac.compare_digestを使用
    if not hmac.compare_digest(calculated_hmac, hmac_from_file):
        raise ValueError('コンテンツのHMACチェックに失敗しました')

    return WUPBOSSInfo(
        hash_type=hash_type,
        iv=iv_full,
        hmac=hmac_from_file,
        content=content
    )

def encrypt_wiiu(
    path_or_buffer: Union[str, bytes], 
    aes_key: str, 
    hmac_key: str,
    _test_iv: Optional[bytes] = None
) -> bytes:
    """
    コンテンツをWii UのBOSSコンテナファイル形式に暗号化します。

    Args:
        path_or_buffer: コンテンツファイルのパス、またはその内容を含むbytesオブジェクト。
        aes_key: BOSSのAESキー（文字列）。
        hmac_key: BOSSのHMACキー（文字列）。
        _test_iv: (テスト用) 12バイトのIVを指定すると、決定論的な出力が得られます。
                  Noneの場合はランダムなIVが生成されます。

    Returns:
        暗号化されたBOSSファイルの内容を表すbytesオブジェクト。
    """
    _verify_keys(aes_key, hmac_key)

    content = _get_data_from_path_or_buffer(path_or_buffer)

    # コンテンツのHMAC-SHA256を計算
    hmac_key_bytes = hmac_key.encode('utf-8')
    h = crypto_hmac.HMAC(hmac_key_bytes, hashes.SHA256())
    h.update(content)
    calculated_hmac = h.finalize()

    # 暗号化の前にHMACをコンテンツの先頭に付加
    payload_to_encrypt = calculated_hmac + content

    # 12バイトのIVを生成
    if _test_iv is not None:
        if len(_test_iv) != 12:
            raise ValueError("_test_ivは12バイトである必要があります。")
        iv_part = _test_iv
    else:
        iv_part = os.urandom(12)
    
    # AES-CTRモード用の16バイトのIVを構築
    counter = b'\x00\x00\x00\x01'
    iv_full = iv_part + counter
    
    # ペイロードを暗号化
    aes_key_bytes = aes_key.encode('utf-8')
    cipher = Cipher(algorithms.AES(aes_key_bytes), modes.CTR(iv_full))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(payload_to_encrypt) + encryptor.finalize()

    # 32バイト(0x20)のヘッダーを構築
    header = bytearray(0x20)

    header[0x0:0x4] = b'boss'
    header[0x4:0x8] = BOSS_WUP_VER.to_bytes(4, 'big')
    header[0x8:0xA] = (1).to_bytes(2, 'big')  # 常に1
    header[0xA:0xC] = (2).to_bytes(2, 'big')  # ハッシュバージョン2
    
    # 12バイトのIVをヘッダーにコピー
    header[0xC:0x18] = iv_part

    # ヘッダーと暗号化されたコンテンツを結合
    return bytes(header) + encrypted