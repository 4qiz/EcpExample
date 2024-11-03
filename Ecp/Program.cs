using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Ecp
{
    internal class Program
    {
        public static void CreatePfx()
        {
            var rsa = RSA.Create(2048);
            var request = new CertificateRequest("cn=YourName", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var cert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

            // Export to PFX
            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, "1");
            File.WriteAllBytes("certificate.pfx", pfxBytes);
        }

        public static void SignDocument()
        {
            string documentPath = "document.txt"; // Path to the document you want to sign
            string certificatePath = "certificate.pfx"; // Path to the PFX file
            string certificatePassword = "1"; // Password for the certificate

            // Load the certificate
            var certificate = new X509Certificate2(certificatePath, certificatePassword);

            // Read the document
            byte[] documentBytes = File.ReadAllBytes(documentPath);

            // Create a SHA256 hash of the document
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(documentBytes);

                // Sign the hash using the private key of the certificate
                using (RSA rsa = certificate.GetRSAPrivateKey())
                {
                    byte[] signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    // Save the signature to a file
                    File.WriteAllBytes("signature.sig", signature);
                    Console.WriteLine("Document signed successfully!");
                }
            }
        }

        public static bool VerifySignature()
        {
            string documentPath = "document.txt"; // Path to the document
            string certificatePath = "certificate.pfx"; // Path to the certificate
            string certificatePassword = "1"; // Password for the certificate
            string signaturePath = "signature.sig"; // Path to the signature file

            // Load the certificate
            var certificate = new X509Certificate2(certificatePath, certificatePassword);

            // Read the document and signature
            byte[] documentBytes = File.ReadAllBytes(documentPath);
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);

            // Create a SHA256 hash of the document
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(documentBytes);

                // Verify the signature using the public key of the certificate
                using (RSA rsa = certificate.GetRSAPublicKey())
                {
                    bool isValid = rsa.VerifyHash(hash, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    if (isValid)
                    {
                        Console.WriteLine("Signature is valid.");
                    }
                    else
                    {
                        Console.WriteLine("Signature is invalid.");
                    }

                    return isValid;
                }
            }
        }

        public static void Main()
        {
            //CreatePfx();
            //SignDocument();
            bool isVerified = VerifySignature();
            Console.WriteLine($"Signature verification result: {isVerified}");
        }
    }
}
