package com.example.sing.verify.controllers;

import com.example.sing.verify.domain.models.SignatureRequest;
import com.example.sing.verify.domain.models.VerifyResponse;
import com.example.sing.verify.services.PKCS7SignatureService;
import com.example.sing.verify.services.SignatureRecordService;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.cms.CMSException;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.LocalDate;

@Controller
@RequestMapping("/signature")
@RequiredArgsConstructor
public class SignatureController {

    private final SignatureRecordService signatureRecordService;

    private final PKCS7SignatureService pkcs7SignatureService;

    @GetMapping("/generate")
    public String showGeneratePage() {
        return "generate-signature";
    }

    @GetMapping("/verify")
    public String showVerifyPage() {
        return "verify-signature";
    }

    @PostMapping("/generate")
    public ResponseEntity<byte[]> generateSignatureFromPdf(@RequestParam("file") MultipartFile file,
                                                           @RequestParam String subjectCN,
                                                           @RequestParam String organization,
                                                           @RequestParam(defaultValue = "KG") String country,
                                                           @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate validFrom,
                                                           @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate validTo,
                                                           @RequestParam(defaultValue = "2048") int keySize) throws Exception {
        SignatureRequest request = new SignatureRequest()
                .setData(file.getBytes())
                .setSubjectCN(subjectCN)
                .setOrganization(organization)
                .setCountry(country)
                .setValidFrom(validFrom)
                .setValidTo(validTo)
                .setKeySize(keySize);

        byte[] signature = pkcs7SignatureService.generatePKCS7Signature(request);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDisposition(ContentDisposition.attachment()
                .filename(file.getOriginalFilename() + ".p7s")
                .build());

        return new ResponseEntity<>(signature, headers, HttpStatus.OK);
    }

    @PostMapping("/verify")
    public String verifySignature(@RequestParam("file") MultipartFile file,
                                  @RequestParam("signature") MultipartFile signature,
                                  @RequestParam(name = "save", required = false) String saveFlag,
                                  Model model) throws IOException, CertificateException, CMSException {
        boolean save = "true".equalsIgnoreCase(saveFlag);

        VerifyResponse response = save
                ? signatureRecordService.verifyAndStore(file.getName(), file.getBytes(), signature.getBytes())
                : signatureRecordService.verify(file.getBytes(), signature.getBytes());

        model.addAttribute("verifyResponse", response);
        model.addAttribute("fileName", file.getOriginalFilename());
        return "verify-signature";
    }
}
