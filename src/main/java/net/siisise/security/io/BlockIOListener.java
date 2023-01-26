/*
 * Copyright 2023 Siisise Net.
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
package net.siisise.security.io;

import java.io.IOException;

/**
 * 特定の長さのブロック単位で渡してくれる便利機能。
 * パディングは管理しない。固定長で供給されることを想定している。
 * IOException が発生する版
 */
public interface BlockIOListener {
    
    /**
     * 必要なブロック長.
     * @return ビット長
     */
    int getBitBlockLength();
  
    /**
     * 非ブロック単位のものをpadding対応して送信するためのもの。
     * ハッシュ計算などでは利用不可。write または flush の単位で暗号にpaddingを詰める想定
     * false の場合は close のみ paddingするか、paddingしない
     * まだない
     */
//    void setFlushPadding(boolean pad);

    /**
     * データが揃ったらところてんで呼び出される.
     * @param src 元配列
     * @param offset データ位置
     * @param length 固定ブロックサイズ(参考)
     * @throws java.io.IOException
     */
    void blockWrite(byte[] src, int offset, int length) throws IOException;
    
    void flush() throws IOException;
    
    /**
     * flush() で呼ばれず closeで呼ばれる 仮Interface
     * @param src
     * @param size max - offset で 1以上 maxまでくらい
     * @throws IOException 
     */
    void blockFlush(byte[] src, int size) throws IOException;

    void close() throws IOException;
}
