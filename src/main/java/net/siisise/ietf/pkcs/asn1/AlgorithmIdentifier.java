package net.siisise.ietf.pkcs.asn1;

import java.util.LinkedHashMap;
import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * PKCS #1 にあるのかもしれない
 * RFC 8017 Appendix C. ASN.1 Module
 * RFC 5911 
 * RFC 5280 X.509v3 Certificate 4.1.1.2
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
        SEQUENCEMap s = new SEQUENCEMap();
        s.put("algorithm", algorithm);
        if ( parameters != null ) {
            s.put("parameters", parameters);
        }
        return s;
    }
    
    public <T> T rebind(TypeFormat<T> format) {
        LinkedHashMap s = new LinkedHashMap();
        s.put("algorithm", algorithm);
        if ( parameters != null ) {
            s.put("parameters", parameters);
        }
        return format.mapFormat(s);
    }

    public static AlgorithmIdentifier decode(SEQUENCE s) {
        AlgorithmIdentifier id = new AlgorithmIdentifier();
        id.algorithm = (OBJECTIDENTIFIER) s.get(0);
        id.parameters = s.get(1);
        return id;
    }
}
