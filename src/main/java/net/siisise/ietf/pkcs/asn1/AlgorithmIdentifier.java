package net.siisise.ietf.pkcs.asn1;

import net.siisise.iso.asn1.ASN1Object;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 * PKCS #1 にあるのかもしれない
 * RFC 8017 Appendix C. ASN.1 Module
 */
public class AlgorithmIdentifier {
    public OBJECTIDENTIFIER algorithm;
    public ASN1Object parameters = new NULL(); // OPTIONAL

    public AlgorithmIdentifier() {
    }

    public AlgorithmIdentifier(OBJECTIDENTIFIER alg) {
        algorithm = alg;
    }

    public AlgorithmIdentifier(String alg) {
        algorithm = new OBJECTIDENTIFIER(alg);
    }

    public AlgorithmIdentifier(OBJECTIDENTIFIER alg, ASN1Object params) {
        algorithm = alg;
        parameters = params;
    }

    public SEQUENCE encodeASN1() {
        SEQUENCE s = new SEQUENCE();
        s.add(algorithm);
        if ( parameters != null ) {
            s.add(parameters);
        }
        return s;
    }
    
    public static AlgorithmIdentifier decode(SEQUENCE s) {
        AlgorithmIdentifier id = new AlgorithmIdentifier();
        id.algorithm = (OBJECTIDENTIFIER) s.get(0);
        id.parameters = s.get(1);
        return id;
    }
}
