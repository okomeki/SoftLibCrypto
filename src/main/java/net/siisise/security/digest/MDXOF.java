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
package net.siisise.security.digest;

/**
 * XOF を MessageDigest として使える変換.
 * @deprecated 今のところXOFはMD継承しているので必要ないかも.
 */
@Deprecated
public class MDXOF extends BlockMessageDigest {

    private final XOF xof;
    
    public MDXOF(XOF xof) {
        super("XOF");
        this.xof = xof;
    }

    @Override
    protected byte[] engineDigest() {
        return xof.digest();
    }

    @Override
    protected void engineReset() {
        xof.digest();
    }

    @Override
    public void blockWrite(byte[] src, int offset, int length) {
        xof.update(src, offset, length);
    }
    
    @Override
    public int getBitBlockLength() {
        return xof.getBitBlockLength();
    }
}
