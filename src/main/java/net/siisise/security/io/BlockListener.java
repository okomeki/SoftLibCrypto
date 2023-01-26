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

/**
 * 特定の長さのブロック単位で渡してくれる便利機能。
 * パディングは管理しない。固定長で供給されることを想定している。
 * IOExceptionが発生しない版
 */
public interface BlockListener extends BlockIOListener {
    
    /**
     * データが揃ったらところてんで呼び出される.
     * @param src 元配列
     * @param offset データ位置
     * @param length 固定ブロックサイズ(参考)
     */
    @Override
    void blockWrite(byte[] src, int offset, int length);
    
    @Override
    void flush();
}
