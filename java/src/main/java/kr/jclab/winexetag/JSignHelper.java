package kr.jclab.winexetag;

import net.jsign.pe.DataDirectory;
import net.jsign.pe.DataDirectoryType;
import net.jsign.pe.PEFile;
import org.bouncycastle.cms.CMSSignedData;

import java.io.IOException;

public class JSignHelper {
    public static void replaceSignature(PEFile peFile, CMSSignedData newSignature) throws IOException {
        DataDirectory certificateTable = peFile.getDataDirectory(DataDirectoryType.CERTIFICATE_TABLE);
        if (certificateTable != null && !certificateTable.isTrailing()) {
            // erase the previous signature
            certificateTable.erase();
            certificateTable.write(0, 0);
        }
        peFile.setSignature(newSignature);
    }
}
