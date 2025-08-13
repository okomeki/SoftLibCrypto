/*
 * Copyright 2025 okome.
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
package net.siisise.itu_t.x501;

import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.ASN1;
import net.siisise.iso.asn1.ASN1Cls;
import net.siisise.iso.asn1.tag.ASN1String;
import net.siisise.iso.asn1.tag.CHOICE;

/**
 * RFC 5280 4.1.2.4.
 * DirectoryString ::= CHOICE {
 *      teletexString     TeletexString (SIZE (1..MAX)),
 *      printableString   PrintableString (SIZE (1..MAX)),
 *      universalString   UniversalString (SIZE (1..MAX)),
 *      utf8String        UTF8String (SIZE (1..MAX)),
 *      bmpString         BMPString (SIZE (1..MAX)) }
 */
public class DirectoryString extends ASN1String {
    
    public DirectoryString(ASN1 tag, String val) {
        super(tag, val);
    }

    public DirectoryString(String val) {
        this(type(val), val);
    }

    /**
     * 仮判定.
     * @param code
     * @return 
     */
    static final ASN1 type(String code) {
        for (char c : code.toCharArray()) {
            if (c >= 0x80) {
                return ASN1.UTF8String;
            }
        }
        return ASN1.PrintableString;
    }

    @Override
    public <T> T rebind(TypeFormat<T> format) {
        CHOICE choice = new CHOICE();
        if (getASN1Cls() == ASN1Cls.UNIVERSAL) {
            String name;
            switch( getId() ) {
                case 0x0C: // UTF8String
                    name = "utf8String";
                    break;
                case 0x13: // PrintableString
                    name = "printableString";
                    break;
                // 以下廃止
                case 0x14: // TeletexString
                    name = "teletexString";
                    break;
                case 0x1C: // UniversalString
                    name = "universalString";
                    break;
                case 0x1E: // BMPString
                    name = "bmpString";
                    break;
                default:
                    throw new IllegalStateException();
            }
            choice.put(name, getValue());
            return (T)format.enumFormat(choice);
        } else {
            return format.stringFormat(getValue());
        }
    }
}
