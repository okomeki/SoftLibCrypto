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

import net.siisise.iso.asn1.annotation.Choice;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;

/**
 * RFC 5280
 * Name ::= CHOICE { rdnSequence RDNSequence }
 * X.500 または LDAP
 * RFC 4519 attribute type
 */
@Choice
public class Name {
    public RDNSequence rdnSequence;
    
    public static final OBJECTIDENTIFIER ID_AT = new OBJECTIDENTIFIER("2.5.4");
    /**
     * LDAP c X.500 CountryName.
     * ISO 3166 two-letter
     * id-at-countryName
     * PrintableString (SIZE (2))
     */
    public static final OBJECTIDENTIFIER COUNTRY = ID_AT.sub(6); // 国名
//    public static final OBJECTIDENTIFIER C = COUNTRY; // 国名
    /**
     * RFC 4519 o X.520 organizationName
     * id-at-organizationName
     * DirectoryName (teletexString, printableString, universalString, utf8String, bmpString)
     */
    public static final OBJECTIDENTIFIER ORGANIZATION_NAME = ID_AT.sub(10); // 組織名
//    public static final OBJECTIDENTIFIER O = ORGANIZATION_NAME;
    /**
     * id-at-organizationUnitName
     * DirectoryName (teletexString, printableString, universalString, utf8String, bmpString)
     */
    public static final OBJECTIDENTIFIER ORGANIZATIONAL_UNIT = ID_AT.sub(11); // 組織単位名
    /**
     * RFC 4519 X.520 dnQualifier
     * 
     * id-at-dnQualifier
     * PrintableString
     */
    public static final OBJECTIDENTIFIER DISTINGUISHED_NAME_QUALIFIER = ID_AT.sub(46); // 組織別修飾子
    public static final OBJECTIDENTIFIER DN_QUALIFIER = DISTINGUISHED_NAME_QUALIFIER;

    public static final OBJECTIDENTIFIER STATE_OR_PROVINCE_NAME = ID_AT.sub(8); // 州名, 県名
    /**
     * LDAP CN X.500 CommonName
     */
    public static final OBJECTIDENTIFIER COMMON_NAME = ID_AT.sub(3); // 共通名
//    public static final OBJECTIDENTIFIER CN = COMMON_NAME;
    /**
     * id-at-serialNumber
     * PrintableString (SIZE (1..ub-serial-number)) 64
     */
    public static final OBJECTIDENTIFIER SERIAL_NUMBER = ID_AT.sub(5); // シリアル番号

    /**
     * RFC 4519 l localityName X.520
     */
    public static final OBJECTIDENTIFIER LOCALITY = ID_AT.sub(7); // 地域
    public static final OBJECTIDENTIFIER L = LOCALITY;
    /**
     * id-at-title
     * DirectoryName (teletexString, printableString, universalString, utf8String, bmpString)
     */
    public static final OBJECTIDENTIFIER TITLE = ID_AT.sub(12); // 敬称
    public static final OBJECTIDENTIFIER SURNAME = ID_AT.sub(4); // 姓
    /**
     * RFC 4519 givenName X.520
     */
    public static final OBJECTIDENTIFIER GIVEN_NAME = ID_AT.sub(42); // 名
    public static final OBJECTIDENTIFIER INITIALS = ID_AT.sub(43); // イニシャル
    /**
     * id-at-pseudonym
     * DirectoryName (teletexString, printableString, universalString, utf8String, bmpString)
     */
    public static final OBJECTIDENTIFIER PSEUDONYM = ID_AT.sub(65); // 仮名
    public static final OBJECTIDENTIFIER GENERATION_QUALIFIER = ID_AT.sub(44); // 世代修飾子

    /**
     * RFC 4519 2.18. name X.520
     * 使わないかも?
     */
    public static final OBJECTIDENTIFIER NAME = ID_AT.sub(41); // 名
    /**
     * LDAP dc RFC 1274 domainComponent
     * id-domainComponent
     * IA5String
     */
    public static final OBJECTIDENTIFIER DOMAIN_COMPONENT = new OBJECTIDENTIFIER("0.9.2342.19200300.100.1.25");
//    public static final OBJECTIDENTIFIER DC = DOMAIN_COMPONENT;
    /**
     * id-emailAddress Legacy
     * IA5String
     */
    public static final OBJECTIDENTIFIER EMAIL_ADDRESS = new OBJECTIDENTIFIER("1.2.840.113549.1.9.1");
    

    // RFC 4519 X.520 のみ?
    public static final OBJECTIDENTIFIER BUSINESS_CATEGORY = ID_AT.sub(15);
    /**
     * RFC 4519 2.5. description X.520
     */
    public static final OBJECTIDENTIFIER DESCRIPTION = ID_AT.sub(13);
    
    /**
     * RFC 4519 2,6. destinationIndicator X.520
     */
    public static final OBJECTIDENTIFIER DESTINTAION_INDICATOR = ID_AT.sub(27);

    /**
     * RFC 4519 2.7. distinguishedName X.520
     */
    public static final OBJECTIDENTIFIER DISTINGUISHED_NAME = ID_AT.sub(49);
    
    /**
     * RFC 4519 2.9. enhancedSearchGuide X.520
     */
    public static final OBJECTIDENTIFIER ENHANCED_SEARCH_GUIDE = ID_AT.sub(47);
    
    /**
     * RFC 4519 2.17. member X.520
     */
    public static final OBJECTIDENTIFIER MEMBER = ID_AT.sub(31);

    static final Object[][] X500NAMES = {
        {"C", COUNTRY},
        {"ST", STATE_OR_PROVINCE_NAME},
        {"O", ORGANIZATION_NAME},
        {"OU", ORGANIZATIONAL_UNIT},
        {"CN", COMMON_NAME}
    };
    
    static OBJECTIDENTIFIER toOID(String name) {
        for ( Object[] o : X500NAMES ) {
            if ( o[0].equals(name)) {
                return (OBJECTIDENTIFIER)o[1];
            }
        }
        return null;
    }
    
    /**
     * ToDo: まともなParser
     * 
     * @param name / 区切り
     * @return Name
     */
    public static Name name(String name) {
        Name n = new Name();
        String[] tav = name.split("/");
        // RDNSequence
        n.rdnSequence = new RDNSequence();
        for ( String v : tav ) {
            if (v.isEmpty()) continue;
            String[] nv = v.split("=", 2);
            AttributeTypeAndValue atav = new AttributeTypeAndValue();
            atav.type = toOID(nv[0]);
            if (atav.type == null ) {
                return null;
            }
            atav.value = new DirectoryString(nv[1]);
            RelativeDistinguishedName rdn = new RelativeDistinguishedName();
            rdn.add(atav);
            n.rdnSequence.add(rdn);
        }
        return n;
    }
}
