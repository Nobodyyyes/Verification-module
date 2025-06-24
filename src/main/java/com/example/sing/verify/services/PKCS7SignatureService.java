package com.example.sing.verify.services;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public interface PKCS7SignatureService {

    byte[] generatePKCS7Signature(byte[] dataToSign) throws NoSuchAlgorithmException, CMSException, IOException, OperatorCreationException, CertificateException;
}
