package com.oci.security.keyvault.jca.implementation.certificates;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static java.util.logging.Level.INFO;
import java.util.logging.Logger;

import com.oci.security.keyvault.jca.implementation.OCIKeyVaultClient;

public class OCISignedCSRCertificates implements OCICertificates{
	
	private final String certificatePath;
	private final String keyId;
	private final OCIKeyVaultClient ociClient;
	/**
     * Stores the list of aliases.
     */
	 /**
     * Stores the specific path aliases.
     */
    private final List<String> aliases = new ArrayList<>();

    /**
     * Stores the specific path certificates by alias.
     */
    private final Map<String, Certificate> certificates = new HashMap<>();

    /**
     * Stores the specific path certificate keys by alias.
     */
    private final Map<String, Key> certificateKeys = new HashMap<>();
    
    private static final Logger LOGGER = Logger.getLogger(OCISignedCSRCertificates.class.getName());

    @Override
    public List<String> getAliases() {
    	LOGGER.log(INFO, "OCISignedCSRCertificates getAliases is invoked with aliases {0}", aliases);
        return aliases;
    }

    @Override
    public Map<String, Certificate> getCertificates() {
    	LOGGER.log(INFO, "OCISignedCSRCertificates getCertificates is invoked");
        return certificates;
    }

    @Override
    public Map<String, Key> getCertificateKeys() {
    	LOGGER.log(INFO, "OCISignedCSRCertificates getCertificateKeys is invoked");
        return certificateKeys;
    }

    @Override
    public void deleteEntry(String alias) {
    	LOGGER.log(INFO, "OCISignedCSRCertificates deleteEntry is invoked for the alias {0}", alias);
        aliases.remove(alias);
        certificates.remove(alias);
        certificateKeys.remove(alias);
    }
    
    @Override
    public Certificate getCertificate(String alias) {
    	LOGGER.log(INFO, "OCISignedCSRCertificates getCertificate is invoked for the alias {0}", alias);
    	return certificates.get(alias);
    }
    
    @Override
    public Key getKey(String alias) {
    	LOGGER.log(INFO, "OCISignedCSRCertificates getKey is invoked for the alias {0}", alias);
    	return certificateKeys.get(alias);
    }

    /**
     * Constructor.
     *
     * @param certificatePath Store the file path where certificates are placed
     * @param keyId
     * @param certificateAuthorityId
     * @param cryptoEndpoint
     */
    public OCISignedCSRCertificates(String certificatePath, String keyId, String certificateAuthorityId,String cryptoEndpoint) {
    	LOGGER.log(INFO, "OCISignedCSRCertificates Constructor is invoked for the Certificate {0}", certificatePath);
        this.certificatePath = certificatePath;
        this.keyId = keyId;
        ociClient = new OCIKeyVaultClient(certificateAuthorityId, cryptoEndpoint);
        loadCertificatesFromSpecificPath(this.certificatePath);
    }

    /**
     * Add alias and certificate
     *
     * @param alias       certificate alias
     * @param certificate certificate value
     */
    public void setCertificateEntry(String alias, Certificate certificate) {
        if (aliases.contains(alias)) {
            LOGGER.log(INFO, "Cannot load certificates with the same alias in specific path {0}", alias);
            return;
        }
        aliases.add(alias);
        certificates.put(alias, certificate);
        certificateKeys.put(alias, ociClient.getPrivateKey(keyId));
    }

    /**
     * If the file can be parsed into a certificate, add it to the list
     *
     * @param file file which try to parsed into a certificate
     * @throws IOException Exception thrown when there is an error in reading all the bytes from the File.
     */
    private void setCertificateByFile(File file) throws IOException {
    	LOGGER.log(INFO, "OCISignedCSRCertificates setCertificateByFile is invoked");
        X509Certificate certificate;
        try (InputStream inputStream = new FileInputStream(file);
            BufferedInputStream bytes = new BufferedInputStream(inputStream)) {
            String alias = getCertificateAlias(file);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(bytes);
            if (certificate != null) {
                setCertificateEntry(alias, certificate);
                LOGGER.log(INFO, "Load certificate for the alias {0}",alias);
            }
        } catch (CertificateException e) {
            LOGGER.log(INFO, "OCISignedCSRCertificates setCertificateByFile Unable to load certificate from: {0}", file.getName());
            LOGGER.log(INFO,"OCISignedCSRCertificates setCertificateByFile Exception: {0}", e.getMessage());
        }
    }

    /**
     * Load certificates in the file directory
     * @param certificatePath certificate path 
     */
    private void loadCertificatesFromSpecificPath(String certificatePath) {
    	LOGGER.log(INFO, "OCISignedCSRCertificates loadCertificatesFromSpecificPath is invoked");
        try {
        	File file = new File(certificatePath);
        	setCertificateByFile(file);
        } catch (IOException ioe) {
            LOGGER.log(INFO, "Unable to determine certificates to specific path", ioe);
        }
    }

    /**
     * Get alias from file
     *
     * @param file File containing certificate information
     * @return certificate alias
     */
    public static String getCertificateAlias(File file) {
        String fileName = file.getName();
        int lastIndexOfDot = fileName.lastIndexOf('.');
        if (lastIndexOfDot == -1) {
            return fileName;
        }
        return fileName.substring(0, lastIndexOfDot);
    }

}
