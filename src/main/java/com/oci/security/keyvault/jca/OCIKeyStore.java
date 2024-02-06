package com.oci.security.keyvault.jca;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;
import java.security.UnrecoverableEntryException;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;
import static java.util.logging.Level.INFO;
import static java.util.logging.Level.SEVERE;

import com.oci.security.keyvault.jca.implementation.certificates.OCIKeyVaultCertificates;
import com.oci.security.keyvault.jca.implementation.certificates.OCISignedCSRCertificates;
import com.oci.security.keyvault.jca.implementation.certificates.OCICertificates;


/**
 * The OCI Key Vault implementation of the KeyStoreSpi.
 *
 * @see KeyStoreSpi
 */
public final class OCIKeyStore extends KeyStoreSpi {

    /**
     * Stores the key-store name.
     */
    public static final String KEY_STORE_TYPE = "OCIKEYVAULT";

    /**
     * Stores the algorithm name.
     */
    public static final String ALGORITHM_NAME = KEY_STORE_TYPE;

    /**
     * Store certificates loaded from KeyVault.
     */
    private OCIKeyVaultCertificates keyVaultCertificates;
    private OCISignedCSRCertificates ociCSRCertificates;
    
    /**
     * Stores the creation date.
     */
    private Date creationDate;

    /**
     * Stores all the certificates.
     */
    private List<OCICertificates> allCertificates;
    
    private static final Logger LOGGER = Logger.getLogger(OCIKeyStore.class.getName());

    public OCIKeyStore() {
    	LOGGER.log(INFO, "OCIKeyStore Constructor is invoked");
    	creationDate = new Date();

        String certAuthorityId = System.getProperty("oci.certAuthorityId");
        String cryptoEndpoint = System.getProperty("oci.cryptoEndpoint");
        String certFile = System.getProperty("oci.certFile");
        String keyId = System.getProperty("oci.keyId");
        
        LOGGER.log(INFO, "OCIKeyStore: CertAuthID: {0}", certAuthorityId);
        LOGGER.log(INFO, "OCIKeyStore: cryptoEndpoint: {0}", cryptoEndpoint);

        keyVaultCertificates = new OCIKeyVaultCertificates(certAuthorityId,cryptoEndpoint);
        LOGGER.log(INFO,"Loaded Key Vault certificates: {0}.",keyVaultCertificates.getAliases());
        
        if(certFile!=null) {
        	ociCSRCertificates = new OCISignedCSRCertificates(certFile,keyId,certAuthorityId,cryptoEndpoint); 
        	LOGGER.log(INFO,"Loaded OCI CSR certificates: {0}.",ociCSRCertificates.getAliases());
        	allCertificates = Arrays.asList(keyVaultCertificates, ociCSRCertificates);
        }
        else {
        	allCertificates = Arrays.asList(keyVaultCertificates);
        }
        LOGGER.log(INFO, "OCIKeyStore Constructor is completed");
    }
    

    /**
     * get key vault key store by system property
     *
     * @return KeyVault key store
     * @throws CertificateException if any of the certificates in the
     *          keystore could not be loaded
     * @throws NoSuchAlgorithmException when algorithm is unavailable.
     * @throws KeyStoreException when no Provider supports a KeyStoreSpi implementation for the specified type
     * @throws IOException when an I/O error occurs.
     */
    public static KeyStore getKeyVaultKeyStoreBySystemProperty() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
    	LOGGER.log(INFO, "OCIKeyStore getKeyVaultKeyStoreBySystemProperty is invoked.");
    	KeyStore keyStore = KeyStore.getInstance(OCIKeyStore.KEY_STORE_TYPE);
        KeyVaultLoadStoreParameter parameter = new KeyVaultLoadStoreParameter(
        	System.getProperty("oci.certAuthorityId"),
        	System.getProperty("oci.cryptoEndpoint")
        );
        keyStore.load(parameter);
        return keyStore;
    }

    /**
     * Lists all the alias names of this keystore.
     *
     * @return enumeration of the alias names
     */
    @Override
    public Enumeration<String> engineAliases() {
    	LOGGER.log(INFO, "OCIKeyStore engineAliases is invoked.");
        return Collections.enumeration(getAllAliases());
    }

    /**
     * Checks if the given alias exists in this keystore.
     *
     * @param alias the alias name
     * @return true if the alias exists, false otherwise
     */
    @Override
    public boolean engineContainsAlias(String alias) {
    	LOGGER.log(INFO, "OCIKeyStore engineContainsAlias is invoked for the alias {0}", alias);
        return engineIsCertificateEntry(alias);
    }

    /**
     * Deletes the entry identified by the given alias from this keystore.
     *
     * @param alias the alias name
     */
    @Override
    public void engineDeleteEntry(String alias) {
    	LOGGER.log(INFO, "OCIKeyStore engineDeleteEntry is invoked for the alias {0}", alias);
        allCertificates.forEach(a -> a.deleteEntry(alias));
    }

    /**
     * Determines if the keystore {@code Entry} for the specified
     * {@code alias} is an instance or subclass of the specified
     * {@code entryClass}.
     *
     * @param alias the alias name
     * @param entryClass the entry class
     * @return true if the keystore {@code Entry} for the specified
     *          {@code alias} is an instance or subclass of the
     *          specified {@code entryClass}, false otherwise
     */
    @Override
    public boolean engineEntryInstanceOf(String alias, Class<? extends KeyStore.Entry> entryClass) {
    	LOGGER.log(INFO, "OCIKeyStore engineEntryInstanceOf is invoked for the alias {0}", alias);
        return super.engineEntryInstanceOf(alias, entryClass);
    }

    /**
     * Get the certificate associated with the given alias.
     *
     * @param alias the alias name
     * @return the certificate, or null if the given alias does not exist or
     * does not contain a certificate
     */
    @Override
    public Certificate engineGetCertificate(String alias) {
    	LOGGER.log(INFO,"OCIKeyStore: engineGetCertificate: is invoked for the alias: {0}", alias);
    	Certificate certificate = null;
    	if(keyVaultCertificates!=null && (keyVaultCertificates.getAliases().contains(alias))) {
    		LOGGER.log(INFO,"OCIKeyStore: engineGetCertificate: cert found in Key Vault {0}", alias);
    		return keyVaultCertificates.getCertificate(alias);	
    	}
    	if(ociCSRCertificates!=null && (ociCSRCertificates.getAliases().contains(alias))) {
    		LOGGER.log(INFO,"OCIKeyStore: engineGetCertificate: cert found in CSR {0}", alias);
    		return ociCSRCertificates.getCertificate(alias);	
    	}
        LOGGER.log(SEVERE, "OCIKeyStore engineGetCertificate is not found. {0}", alias);
        return certificate;
    }

    /**
     * Get the (alias) name of the first keystore entry whose certificate matches the given certificate.
     *
     * @param cert the certificate to match with.
     * @return the alias name of the first entry with matching certificate,
     * or null if no such entry exists in this keystore
     */
    @Override
    public String engineGetCertificateAlias(Certificate cert) {
    	LOGGER.log(INFO, "OCIKeyStore engineGetCertificateAlias is invoked.");
        String alias = null;
        if (cert != null) {
            List<String> aliasList = getAllAliases();
            for (String candidateAlias : aliasList) {
                Certificate certificate = engineGetCertificate(candidateAlias);
                if (certificate!=null && certificate.equals(cert)) {
                    return candidateAlias;
                }
            }
        }
        LOGGER.log(SEVERE, "OCIKeyStore engineGetCertificateAlias Alias is not found for the certificate");
        return alias;
    }

    /**
     * Get the certificate chain associated with the given alias.
     *
     * @param alias the alias name
     * @return the certificate chain (ordered with the user's certificate first
     * and the root certificate authority last), or null if the given alias
     * does not exist or does not contain a certificate chain
     */
    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
    	LOGGER.log(INFO, "OCIKeyStore engineGetCertificateChain is invoked.");
        Certificate[] chain = null;
        Certificate certificate = engineGetCertificate(alias);
        if (certificate != null) {
            chain = new Certificate[1];
            chain[0] = certificate;
        }
        return chain;
    }

    /**
     * Get the creation date of the entry identified by the given alias.
     *
     * @param alias the alias name
     * @return the creation date of this entry, or null if the given alias does not exist
     */
    @Override
    public Date engineGetCreationDate(String alias) {
    	LOGGER.log(INFO, "OCIKeyStore engineGetCreationDate is invoked for the alias {0}", alias);
        return creationDate;
    }

    /**
     * Gets a {@code KeyStore.Entry} for the specified alias with the specified protection parameter.
     *
     * @param alias the alias name
     * @param protParam the protParam
     * @return the {@code KeyStore.Entry} for the specified alias,or {@code null} if there is no such entry
     * @exception KeyStoreException if the operation failed
     * @exception NoSuchAlgorithmException if the algorithm for recovering the entry cannot be found
     * @exception UnrecoverableEntryException if the specified {@code protParam} were insufficient or invalid
     */
    @Override
    public KeyStore.Entry engineGetEntry(String alias, KeyStore.ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
    	LOGGER.log(INFO, "OCIKeyStore engineGetEntry is invoked for the alias {0}", alias);
    	return super.engineGetEntry(alias, protParam);
    }

    /**
     * Get key associated with the given alias.
     *
     * @param alias the alias name
     * @param password the password for recovering the key
     * @return the requested key, or null if the given alias does not exist or does not identify a key-related entry
     */
    @Override
    public Key engineGetKey(String alias, char[] password) {
    	LOGGER.log(INFO, "OCIKeyStore engineGetKey is invoked for the alias: {0}", alias);
    	Key key = null;
    	if(ociCSRCertificates!=null && (ociCSRCertificates.getAliases().contains(alias))) {
			LOGGER.log(INFO,"OCIKeyStore: engineGetKey: cert found in CSR {0}", alias);
			return ociCSRCertificates.getKey(alias);
    	}
    	if(keyVaultCertificates!=null && (keyVaultCertificates.getAliases().contains(alias))) {
    		LOGGER.log(INFO,"OCIKeyStore: engineGetKey: cert found in Key Vault {0}", alias);
    		return keyVaultCertificates.getKey(alias);
    	}
    	LOGGER.log(SEVERE, "OCIKeyStore engineGetKey is not found for alias: {0}", alias);
    	return key;
    }

    /**
     * Check whether the entry identified by the given alias contains a trusted certificate.
     *
     * @param alias the alias name
     * @return true if the entry identified by the given alias contains a trusted certificate, false otherwise
     */
    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return getAllAliases().contains(alias);
    }

    /**
     * Check whether the entry identified by the given alias is a key-related.
     *
     * @param alias the alias for the keystore entry to be checked
     * @return true if the entry identified by the given alias is a key-related, false otherwise
     */
    @Override
    public boolean engineIsKeyEntry(String alias) {
        return engineIsCertificateEntry(alias);
    }

    /**
     * Loads the keystore using the given {@code KeyStore.LoadStoreParameter}.
     *
     * @param param the {@code KeyStore.LoadStoreParameter}
     *          that specifies how to load the keystore,
     *          which may be {@code null}
     */
    @Override
    public void engineLoad(KeyStore.LoadStoreParameter param) {
    	LOGGER.log(INFO, "OCIKeyStore engineLoad is invoked.");
    	if (param instanceof KeyVaultLoadStoreParameter) {
            KeyVaultLoadStoreParameter parameter = (KeyVaultLoadStoreParameter) param;
            keyVaultCertificates.updateKeyVaultClient(parameter.getCertAuthorityId(),parameter.getCryptoEndpoint());
        }
    }

    /**
     * Loads the keystore from the given input stream.
     *
     * @param stream the input stream from which the keystore is loaded,or {@code null}
     * @param password the password
     */
    @Override
    public void engineLoad(InputStream stream, char[] password) {
    	LOGGER.log(INFO, "OCIKeyStore engineLoad is invoked with input stream");
    }

    private List<String> getAllAliases() {
    	LOGGER.log(INFO, "OCIKeyStore getAllAliases is invoked");
        List<String> allAliases = new ArrayList<>(keyVaultCertificates.getAliases());
        if(ociCSRCertificates!=null) {
        	allAliases.addAll(ociCSRCertificates.getAliases());
        }
        return allAliases;
    }

    /**
     * Assigns the given certificate to the given alias.
     *
     * @param alias the alias name
     * @param certificate the certificate
     */
    @Override
    public void engineSetCertificateEntry(String alias, Certificate certificate) {
    	LOGGER.log(INFO, "OCIKeyStore engineSetCertificateEntry is invoked for the alias {0}", alias);
    }


    /**
     * Assigns the given key to the given alias, protecting it with the given password.
     *
     * @param alias the alias name
     * @param key the key to be associated with the alias
     * @param password the password to protect the key
     * @param chain the certificate chain
     */
    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
    	LOGGER.log(INFO, "OCIKeyStore engineSetKeyEntry is invoked for the alias {0}", alias);
    }

    /**
     * Assigns the given key (that has already been protected) to the given alias.
     *
     * @param alias the alias name
     * @param key the key
     * @param chain the certificate chain
     */
    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
    	LOGGER.log(INFO, "OCIKeyStore engineSetKeyEntry is invoked for the alias {0}", alias);
    }

    /**
     * Retrieves the number of entries in this keystore.
     *
     * @return the number of entries in this keystore
     */
    @Override
    public int engineSize() {
        return getAllAliases().size();
    }

    /**
     * Stores this keystore to the given output stream, and protects its integrity with the given password.
     *
     * @param stream the output stream to which this keystore is written
     * @param password the password to generate the keystore integrity check
     */
    @Override
    public void engineStore(OutputStream stream, char[] password) {
    	LOGGER.log(INFO, "OCIKeyStore engineStore is invoked with stream");
    }

    /**
     * Stores this keystore using the given.
     *
     * @param param the param
     */
    @Override
    public void engineStore(KeyStore.LoadStoreParameter param) {
    	LOGGER.log(INFO, "OCIKeyStore engineStore is invoked with LoadStoreParameter");
    }
}
