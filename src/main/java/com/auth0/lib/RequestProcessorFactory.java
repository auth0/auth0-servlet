package com.auth0.lib;

import com.auth0.jwk.JwkProvider;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

class RequestProcessorFactory {

    private static final String RSA_CERTIFICATE_HEADER = "-----BEGIN CERTIFICATE-----";

    RequestProcessor forCodeGrant(APIClientHelper clientHelper, TokensCallback callback) {
        return new RequestProcessor(clientHelper, callback);
    }

    RequestProcessor forImplicitGrantHS(APIClientHelper clientHelper, String clientSecret, String domain, String clientId, TokensCallback callback) throws UnsupportedEncodingException {
        TokenVerifier verifier = new TokenVerifier(clientSecret, clientId, domain);
        return new RequestProcessor(clientHelper, verifier, callback);
    }

    RequestProcessor forImplicitGrantRS(APIClientHelper clientHelper, JwkProvider jwkProvider, String domain, String clientId, TokensCallback callback) throws IOException {
        TokenVerifier verifier = new TokenVerifier(jwkProvider, clientId, domain);
        return new RequestProcessor(clientHelper, verifier, callback);
    }


    /**
     * Read the bytes of a PKCS8 RSA Public Key or Certificate.
     *
     * @param path the RSA certificate or public key file path.
     * @return the parsed RSA Public Key.
     * @throws IOException if something happened when trying to parse the certificate bytes.
     */
    //Visible for testing
    @SuppressWarnings("WeakerAccess")
    static RSAPublicKey readPublicKeyFromFile(final String path) throws IOException {
        Validate.notNull(path);
        Scanner scanner = null;
        PemReader pemReader = null;
        try {
            scanner = new Scanner(Paths.get(path));
            if (scanner.hasNextLine() && scanner.nextLine().startsWith(RSA_CERTIFICATE_HEADER)) {
                FileInputStream fs = new FileInputStream(path);
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                X509Certificate cer = (X509Certificate) fact.generateCertificate(fs);
                PublicKey key = cer.getPublicKey();
                fs.close();
                return (RSAPublicKey) key;
            } else {
                pemReader = new PemReader(new FileReader(path));
                byte[] keyBytes = pemReader.readPemObject().getContent();
                KeyFactory kf = KeyFactory.getInstance("RSA");
                EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                return (RSAPublicKey) kf.generatePublic(keySpec);
            }
        } catch (Exception e) {
            throw new IOException("Couldn't parse the RSA Public Key / Certificate file.", e);
        } finally {
            if (scanner != null) {
                scanner.close();
            }
            if (pemReader != null) {
                pemReader.close();
            }
        }
    }
}
