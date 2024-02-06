package com.oci.security.keyvault.jca.implementation.certificates;

import java.security.Key;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Map;

/**
 * Store OCI Certificates
 */
public interface OCICertificates {

    /**
     * Get certificate aliases.
     * @return certificate aliases
     */
    List<String> getAliases();

    /**
     * Get certificates.
     * @return certificates
     */
    Map<String, Certificate> getCertificates();

    /**
     * Get certificate keys.
     * @return certificate keys
     */
    Map<String, Key> getCertificateKeys();

    /**
     * Delete certificate info by alias if exits
     * @param alias certificate alias
     */
    void deleteEntry(String alias);
    
    /**
     * Get certificate by alias if exits
     * @param alias certificate alias
     */
    Certificate getCertificate(String alias);
    
    /**
     * Get Key by alias if exits
     * @param alias certificate alias
     */
    Key getKey(String alias);
}