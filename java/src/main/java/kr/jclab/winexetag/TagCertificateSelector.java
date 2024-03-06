package kr.jclab.winexetag;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Selector;

public class TagCertificateSelector implements Selector<X509CertificateHolder> {
    public static TagCertificateSelector INSTANCE = new TagCertificateSelector();

    @Override
    public boolean match(X509CertificateHolder obj) {
        for (Object oid : obj.getNonCriticalExtensionOIDs()) {
            if (WinExeTagUtils.TAG_OID_STRING.equals(oid.toString())) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Object clone() {
        return this;
    }
}
