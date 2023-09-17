# SoftLibCrypto
Javaのハッシュ、暗号系ライブラリです

ブロック、ハッシュ、など基本的なところをJava標準と同じくらいまで充実させたいところです。
速度的にはCPUのあれを使っていない分標準よりは遅いのですが、AESなどはソフト実装の中では高速な部類です。
JCAは準備中かな。

モジュール別なので、HMAC と SHA-3 など組み合わせの自由度は高めです。

現状 SoftLib に依存しないように分けていますが、依存関係になる日も近いかもしれません。
PKI系のものは別途パッケージにする予定です。

## Block 暗号
AES,DES,TripleDES など

## 暗号モード
CBC,ECB,CTRなどまだ少ない

GCM 仮

# padding
まだ少ない

## Stream 暗号

## Message Dugest
MD2,MD4,MD5,SHA-1,SHA-2系,SHA-3系

## MAC
HMAC (HMAC-SHA1など),CMAC (OMAC1, RFC 4493 AES-CMACなど), OMAC2

HMAC-MD2
HMAC-MD4
HMAC-MD5
HMAC-SHA-224
HMAC-SHA-256
HMAC-SHA-384
HMAC-SHA-512
HMAC-SHA-512/224
HMAC-SHA-512/256
HMAC-SHA3-224
HMAC-SHA3-256
HMAC-SHA3-384
HMAC-SHA3-512
などSoftLibCrypto で対応しているHashはすべてHMACも対応

CMAC (128bit,64bit 汎用)
RFC 4493 AES-CMAC
RFC 4494 AES-CMAC-96 まだ
AES-128 AES-192 AES-256 ほか128bit暗号は対応できそう

## 速度
code | JDK (OpenSSL AES-NI) | SoftLib
-----|----|------
AES-CBC encode | 2608 | 1510 
AES-CBC decode | 2716 | 1144

JDKのCBCが遅いのでAES-NIの半分くらいは出てる

# License

Apache 2.0 License としたいです。

# Maven

~~~
<dependency>
    <groupId>net.siisise</groupId>
    <artifactId>softlib-crypto</artifactId>
    <version>1.0.2</version>
    <scope>test</scope>
    <type>jar</type>
</dependency>
~~~
バージョンは 1.0.2 です。
開発版は1.0.3-SNAPSHOTかも。


