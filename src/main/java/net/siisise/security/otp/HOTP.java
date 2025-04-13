/*
 * Copyright 2023 okome.
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
package net.siisise.security.otp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA1;
import net.siisise.security.mac.HMAC;
import net.siisise.security.mac.MAC;

/**
 * RFC 4226 HOTP
 */
public class HOTP implements OTP {
//    MessageDigest prf;

    private MAC mac;

    private byte[] K;

//    int Digit = 6;
    private long Drange;
    /**
     * すろっとるぱらめーた.
     * T回の認証試行が失敗すると、サーバーはユーザーからの接続を拒否します。
     */
    private int T;

    /**
     * 再同期パラメータ.
     *
     */
    private int s;

    public HOTP(MAC mac) {
        this.mac = mac;
    }

    /**
     * HMACのハッシュ関数を指定して作成.
     * HMAC-SHA-1 なら SHA-1
     * ブロック長が取得できるとよい
     *
     * @param prf ハッシュ関数.
     */
    public HOTP(MessageDigest prf) {
        this(new HMAC(prf));
    }

    public HOTP(SecretKey key) {
        this(new HMAC(key));

    }

    /**
     * HMAC-SHA1 初期化.
     */
    public HOTP() {
        this(new SHA1());
    }

    /**
     * 鍵生成.
     * @return 鍵
     * @throws NoSuchAlgorithmException 
     */
    public byte[] genKey() throws NoSuchAlgorithmException {
        int ml = mac.getMacLength();
        byte[] key = new byte[ml];
        SecureRandom srnd = SecureRandom.getInstanceStrong();
        srnd.nextBytes(key);
//        setKey(key);
        this.K = key;
        mac.init(K);
        return key;
    }

    public void setKey(byte[] K) {
        this.K = new byte[K.length];
        System.arraycopy(K, 0, this.K, 0, K.length);
        mac.init(this.K);
    }

    /**
     * 出力桁指定.
     *
     * @param digit 出力桁数 4から8か9ぐらい
     */
    void setDigit(int digit) {
        Drange = 1;
        for (int i = 0; i < digit; i++) {
            Drange *= 10;
        }
    }

    /**
     * リトライ可能数取得. (仮
     *
     * @return
     */
    public int getRetly() {
        return T;
    }

    /**
     * リトライ可能数設定.
     *
     * @param retry
     */
    public void setRetry(int retry) {
        T = retry;
    }

    /**
     * 設定.
     * カウンタ値以外.
     *
     * @param K 鍵
     * @param digit 桁数
     * @param t リトライ可能数 (仮
     * @param s 再同期パラメータ (仮
     */
    public void init(byte[] K, int digit, int t, int s) {
        setKey(K);
        setDigit(digit);
        setRetry(t);
        this.s = s;
    }

    /**
     * Section 5.2.
     *
     * @param counter C カウンター 8バイト
     * @return D
     */
    @Override
    public String generateOTP(byte[] counter) {
        byte[] hs = mac.doFinal(counter);
        long otp = (DT(hs) % Drange);
        return Long.toString(Drange + otp).substring(1);
    }

    public String generateOTP(long counter) {
        return generateOTP(Bin.ltob(new long[]{counter}));
    }

    /**
     * 判定用.
     *
     * @param P
     * @prarm counter 8バイト
     * @return
     */
    public boolean validate(int P, byte[] counter) {
        if (T <= 0) {
            return false;
        }
        generateOTP(counter);
        throw new UnsupportedOperationException();
    }

    /**
     * Section 5.3.
     *
     * @param hs HMACの出力
     * @return Snum
     */
    int DT(byte[] hs) {
        int offset = hs[hs.length - 1] & 0x0f;
        int P = 0;
        for (int i = offset; i < offset + 4; i++) {
            P <<= 8;
            P |= hs[i] & 0xff;
        }
        return P & 0x7fffffff;
    }
}
