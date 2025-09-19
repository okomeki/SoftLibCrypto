/*
 * Copyright 2024 okome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.siisise.security.sign;

import net.siisise.security.ec.EdWards448;
import net.siisise.security.ec.EdWards25519;
import net.siisise.security.ec.EdWards;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import net.siisise.io.Output;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.lang.Bin;
import net.siisise.security.digest.BlockMessageDigest;
import net.siisise.security.key.EdDSAPrivateKey;
import net.siisise.security.key.EdDSAPublicKey;

/**
 * RFC 8032 EdDSA nonce 確定的
 * 公開鍵 32byte 256bit
 * 秘密鍵
 * 署名 64byte 512bit
 */
public class EdDSA extends Output.AbstractOutput implements SignVerify {

    public static final OBJECTIDENTIFIER X25519 = new OBJECTIDENTIFIER("1.3.101.110");
    public static final OBJECTIDENTIFIER X448 = new OBJECTIDENTIFIER("1.3.101.111");
    public static final OBJECTIDENTIFIER Ed25519 = new OBJECTIDENTIFIER("1.3.101.112");
    public static final OBJECTIDENTIFIER Ed448 = new OBJECTIDENTIFIER("1.3.101.113");

    public static EdWards25519 init25519() {
        return new EdWards25519();
    }

    public static EdWards448 init448() {
        return new EdWards448();
    }

    /**
     * Ed25519 32byte 256bit
     * Ed448
     */
    EdDSAPrivateKey pkey;
    EdDSAPublicKey pubKey;
    BlockMessageDigest H;

    byte[] dom;
    PacketA block = new PacketA();

    public EdDSA() {
    }

    public EdDSA(EdDSAPrivateKey k) {
        this(k, null);
    }

    public EdDSA(EdDSAPrivateKey k, byte[] context) {
        pkey = k;
        EdWards curve = k.getCurve();
        if (context != null && context.length > 0) {
            dom = curve.dom(0, context);
        } else {
            dom = curve.id();
        }
        preSign();
    }

    public EdDSA(EdDSAPublicKey pub) {
        pubKey = pub;
        dom = pub.getCurve().id();
    }

    /**
     * 秘密鍵長?
     *
     * @return 秘密鍵長(バイト)
     */
    @Override
    public int getKeyLength() {
        return pkey.getCurve().b / 8;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        if (pkey != null) {
            H.update(src, offset, length);
        }
        block.write(src, offset, length);
    }

    /**
     * 秘密鍵.
     * RFC 8410 CurvePrivateKey の形式
     * PKCS #8 の privateKey OCTETSTRING
     *
     * @param curve 曲線
     * @return OCTETSTRING な形式?
     */
    public byte[] genPrvKey(EdWards curve) {
        byte[] key = new byte[curve.b / 8]; // ?
        SecureRandom srnd;
        try {
            srnd = SecureRandom.getInstanceStrong();
            srnd.nextBytes(key);
            pkey = new EdDSAPrivateKey(curve, key);
            dom = curve.id();
            preSign();
            OCTETSTRING oct = new OCTETSTRING(key);
            ASN1DERFormat der = new ASN1DERFormat();
            return oct.rebind(der);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * 5.1.5. 鍵の生成
     * 公開鍵
     *
     * @return 公開鍵
     */
    public byte[] genPubKey() {
        if (pubKey == null) {
            pubKey = pkey.getPublicKey();
        }
        return pubKey.getA();
    }

    void preSign() {
        byte[] prefix = pkey.getPrefix();
        EdWards curve = pkey.getCurve();
        H = curve.H();
        H.update(dom);
        H.update(prefix);
    }

    /**
     * RFC 8032 5.1.6. Sign
     * RFC 8032 5.2.6. Sign
     * 2.のPH(M)の後、r生成から
     */
    @Override
    public byte[] sign() {
        EdWards curve = pkey.getCurve();
        // 2.
        BigInteger r = Bin.lbtobi(H.digest()).mod(curve.L);
        // 3.
        byte[] R = curve.nE(r); // チェック済み
        H.update(dom);
        H.update(R);
        H.update(pkey.getA());
        byte[] phM = block.toByteArray(); //curve.PH(); // PH(M)
        H.update(phM);

        BigInteger k = Bin.lbtobi(H.digest()).mod(curve.L);
        BigInteger s = pkey.gets();
        byte[] S = curve.ENC(r.add(k.multiply(s)));
        PacketA d = new PacketA();
        d.dwrite(R);
        d.dwrite(S);

        preSign();
        return d.toByteArray();
    }

    /**
     * 検証. Verify.
     *
     * @param sign R | S
     * @return
     */
    @Override
    public boolean verify(byte[] sign) {
        byte[] Ab = genPubKey();
        EdWards curve = pubKey.getCurve();
        int hlen = curve.b / 8;
        byte[] Rb = Arrays.copyOfRange(sign, 0, hlen);
        BigInteger S = Bin.lbtobi(Arrays.copyOfRange(sign, hlen, hlen * 2));
        if (S.compareTo(curve.L) >= 0) {
            throw new IllegalStateException();
        }
        byte[] phM = block.toByteArray();
        H = curve.H();
        H.update(dom);
        H.update(Rb);
        H.update(Ab);
        byte[] h = H.digest(phM);
        BigInteger k = Bin.lbtobi(h).mod(curve.L);
        EdWards.Point R = curve.decXY(Rb);
        EdWards.Point A = curve.decXY(Ab);
        EdWards.Point RkA = R.add(A.nE(k));
        EdWards.Point SB = curve.B.nE(S);
        return SB.equals(RkA);
    }
}
