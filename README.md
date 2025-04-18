# SoftLibCrypto
Javaのハッシュ、暗号系ライブラリです
Java hashing and cryptographic library

ブロック、ハッシュ、など基本的なところをJava標準と同じくらいまで充実させたいところです。
速度的にはCPUのあれを使っていない分標準よりは遅いのですが、AESなどはソフト実装の中では高速な部類です。
JCAは準備中かな。

モジュール別なので、HMAC と SHA-3 など組み合わせの自由度は高めです。

PKI系のものは別途パッケージにする予定です。

## PKCS
ASN.1 DER対応なども別パッケージになっているので
- PKCS #1 RSA 全機能
- PKCS #5 Password base 全機能
  - SHA-3系対応済み
- PKCS #8
ぐらいなら気軽に対応している

## 公開鍵暗号,署名
PKCS #1 ぜんぶ RSA系
- RSAEP
- RSADP
- RSASP1
- RSAVP1
- RSAES-OAEP
  - EME-OAEP
- RSAES-PKCS1-v1.5
  - EME-PKCS1_v1_5
- RSASSA-PSS
- RSASSA-PKCS1_v1_5
など

## 共通鍵 Block 暗号
- AES
- DES(DEA)
- TripleDES(TDEA)
- RC2
- Blowfish

など

## 暗号モード
- CBC
- CFB
- ECB
- CTR
- OFB
- etc

暗号との組み合わせは自由

認証付き

- GCM 1.0.3くらいから スレッド対応
- CCM 1.0.7くらい

# padding
- PKCS7Padding

まだ少ない

# パスワード系
- KDF1,2,3
- HKDF
- PKCS #5
  - PBKDF1
  - PBKDF2
  - PBES1
  - PBES2
- KMACKDF
- OpenSSL
  - PBKDF1改
- etc...

## Stream 暗号

## Message Digest
- MD2
- MD4
- MD5
- SHA-1
- SHA-2系
- Keccak
  - SHA-3系
  - SHAKE128
  - SHAKE256
  - cSHAKE128
  - cSHAKE256
  - TupleHash128
  - TupleHash256
  - TupleHashXOF128
  - TupleHashXOF256
  - ParallelHash128
  - ParallelHash256
  - ParallelHashXOF128
  - ParallelHashXOF256

## MAC
鍵つきハッシュみたいなの

- HMAC (HMAC-SHA1など)
- CMAC (OMAC1, RFC 4493 AES-CMACなど)
- OMAC2
- KMAC
- XCBC
- MacCBC
- NMAC RFC 6151
- etc...

などブロック暗号,ハッシュとの組み合わせは自由

例

- HMAC-MD2
- HMAC-MD4
- HMAC-MD5
- HMAC-SHA-224
- HMAC-SHA-256
- HMAC-SHA-384
- HMAC-SHA-512
- HMAC-SHA-512/224
- HMAC-SHA-512/256
- HMAC-SHA3-224
- HMAC-SHA3-256
- HMAC-SHA3-384
- HMAC-SHA3-512
- AES-CMAC

CMAC (128bit,64bit 汎用)
RFC 4493 AES-CMAC
RFC 4494 AES-CMAC-96 まだ
AES-128 AES-192 AES-256
TDEA-CMAC
ほか64bit, 128bit暗号は対応できそう

## ASN.1
- BER
- DER
- PEM

XML,JSON,Javaなど相互変換
PKCS #8,#9,#12 鍵の符号化などは一部対応

## 速度
code | JDK (OpenSSL AES-NI) | SoftLib
-----|----|------
AES-CBC encode | 2608 | 1510 
AES-CBC decode | 2716 | 1144
AES-GCM encode |  591 | 1457
AES-GCM decode | 3237 | 1531

CBC AMD Ryzen 2600X か 5800Xの値

GCM AMD Ryzen 5800X

JDKの暗号はAES-NIの割に遅いのでAES-NIの半分くらいは出てる さらにJDKのGCMはなぜか遅い

# License

Apache 2.0 License としたいです。

# Maven

JDK11以降用 module対応っぽい版
~~~
<dependency>
    <groupId>net.siisise</groupId>
    <artifactId>softlib-crypto.module</artifactId>
    <version>1.0.7</version>
    <type>jar</type>
</dependency>
~~~
JDK8用
~~~
<dependency>
    <groupId>net.siisise</groupId>
    <artifactId>softlib-crypto</artifactId>
    <version>1.0.7</version>
    <type>jar</type>
</dependency>
~~~
バージョンは 1.0.7 です。
開発版は1.0.8-SNAPSHOTかも。


