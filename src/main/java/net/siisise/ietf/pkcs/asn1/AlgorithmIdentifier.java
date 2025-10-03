package net.siisise.ietf.pkcs.asn1;

import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * X.509 にあるのかもしれない.
 * RFC 5280 X.509v3 Certificate 4.1.1.2
 * RFC 8017 Appendix C. ASN.1 Module
 * RFC 5911 
 * RFC 5912 最新版?
 */
public class AlgorithmIdentifier {
    public OBJECTIDENTIFIER algorithm;
    public ASN1Tag parameters = new NULL(); // OPTIONAL

    public AlgorithmIdentifier() {
    }

    public AlgorithmIdentifier(OBJECTIDENTIFIER alg) {
        algorithm = alg;
    }

    public AlgorithmIdentifier(String alg) {
        algorithm = new OBJECTIDENTIFIER(alg);
    }

    public AlgorithmIdentifier(OBJECTIDENTIFIER alg, ASN1Tag params) {
        algorithm = alg;
        parameters = params;
    }

    public SEQUENCEMap encodeASN1() {
        return (SEQUENCEMap)rebind(new ASN1Convert());
    }
    
    public <T> T rebind(TypeFormat<T> format) {
        SEQUENCEMap s = new SEQUENCEMap();
        s.put("algorithm", algorithm);
        if ( parameters != null ) {
            s.put("parameters", parameters);
        }
        return (T)s.rebind(format);
    }

    /**
     * ASN.1 decode
     * @param s ASN.1
     * @return AI
     */
    public static AlgorithmIdentifier decode(SEQUENCE s) {
        AlgorithmIdentifier id = new AlgorithmIdentifier();
        id.algorithm = (OBJECTIDENTIFIER) s.get("algorithm", 0);
        switch (s.size()) {
            case 1:
                id.parameters = null;
                break;
            case 2:
                id.parameters = s.get("parameters", 1);
                break;
            default:
                throw new IllegalStateException();
        }
        return id;
    }
}
