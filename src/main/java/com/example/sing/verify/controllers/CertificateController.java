package com.example.sing.verify.controllers;

import com.example.sing.verify.domain.models.CertificateInfo;
import com.example.sing.verify.services.CertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequestMapping("/certificate")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;

    @GetMapping("/info")
    public String showCertificateInfoPage() {
        return "certificate-info";
    }

    @PostMapping("/info")
    public String extractCertificate(@RequestParam("signature") MultipartFile signature, Model model) throws Exception {
        CertificateInfo certificateInfo = certificateService.extractCertificateInfo(signature.getBytes());
        model.addAttribute("certInfo", certificateInfo);
        return "certificate-info";
    }
}
