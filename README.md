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
CBC,ECB,などまだ少ない

GCMまだ

# padding
まだ少ない

## Stream 暗号

## Message Dugest
MD2,MD4,MD5,SHA-1,SHA-2系,SHA-3系

## MAC
HMAC

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
    <version>1.0.1</version>
    <scope>test</scope>
    <type>jar</type>
</dependency>
~~~
バージョンは 1.0.1 です。


