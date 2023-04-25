package net.siisise.ietf.pkcs1;

import net.siisise.iso.asn1.ASN1Object;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 * PKCS #1 にあるのかもしれない
 * RFC 8017 Appendix C. ASN.1 Module
 */
public class AlgorithmIdentifier {
    public OBJECTIDENTIFIER algorithm;
    public ASN1Object parameters; // OPTIONAL

    /**
     * X.697 (仮)
     */
    void encodeJSON() {
        
    }

    public SEQUENCE encodeASN1() {
        SEQUENCE s = new SEQUENCE();
        s.add(algorithm);
        s.add(parameters);
        return s;
    }

    public static AlgorithmIdentifier decode(SEQUENCE s) {
        AlgorithmIdentifier id = new AlgorithmIdentifier();
        id.algorithm = (OBJECTIDENTIFIER) s.get(0);
        id.parameters = s.get(1);
        return id;
    }
}
