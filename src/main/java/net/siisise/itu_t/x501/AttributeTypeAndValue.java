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

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;

/**
 * RFC 5280 4.1.2.4. Issuer
 */
public class AttributeTypeAndValue {
    public static final OBJECTIDENTIFIER ID_CE = new OBJECTIDENTIFIER(2,5,29);
    public static final OBJECTIDENTIFIER subjectAltName = ID_CE.sub(17);
    public static final OBJECTIDENTIFIER policyMapping = ID_CE.sub(33);
    
    // AttributeType ::= OBJECT IDENTIFIER
    public OBJECTIDENTIFIER type;
    // AttributeValue ::= ANY -- DEFINED BY AttributeType
/*
    enum DirectoryString {
        ASN1net.siisise.iso.ASN1Object
        
        .;
        .ASN1 s,
    }
*/
    public DirectoryString value;
}
