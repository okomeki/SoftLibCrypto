# SoftLibCrypto
Javaのハッシュ、暗号系ライブラリです
Java hashing and cryptographic library

ブロック、ハッシュ、など基本的なところをJava標準と同じくらいまで充実させたいところです。
速度的にはCPUのあれを使っていない分標準よりは遅いのですが、AESなどはソフト実装の中では高速な部類です。
JCAは準備中かな。

モジュール別なので、HMAC と SHA-3 など組み合わせの自由度は高めです。

PKI系のものは別途パッケージにする予定です。

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
AES,DES(DEA),TripleDES(TDEA),RC2 など

## 暗号モード
- CBC
- ECB
- CTRなど
組み合わせ自由

- GCM 1.0.3くらいから

# padding
PKCS7Padding
まだ少ない

# パスワード系
HKDF
PKCS #5
PBKDF1,2,PBES1,2

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
DER
XML,JSON変換
PKCS #8,#9,#12 鍵の符号化などは一部対応

## 速度
code | JDK (OpenSSL AES-NI) | SoftLib
-----|----|------
AES-CBC encode | 2608 | 1510 
AES-CBC decode | 2716 | 1144
AES-GCM encode |  738 |  329

CBC AMD Ryzen 2600X か 5800Xの値

GCM AMD Ryzen 5800X

JDKの暗号はAES-NIの割に遅いのでAES-NIの半分くらいは出てる

# License

Apache 2.0 License としたいです。

# Maven

JDK11以降用 module対応っぽい版
~~~
<dependency>
    <groupId>net.siisise</groupId>
    <artifactId>softlib-crypto.module</artifactId>
    <version>1.0.3</version>
    <scope>test</scope>
    <type>jar</type>
</dependency>
~~~
JDK8用
~~~
<dependency>
    <groupId>net.siisise</groupId>
    <artifactId>softlib-crypto</artifactId>
    <version>1.0.3</version>
    <scope>test</scope>
    <type>jar</type>
</dependency>
~~~
バージョンは 1.0.3 です。
開発版は1.0.4-SNAPSHOTかも。


