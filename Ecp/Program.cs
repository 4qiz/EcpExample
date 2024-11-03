using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Ecp
{
    internal class Program
    {
        public static void Main()
        {
            string certificatePassword = "password"; // password PFX
            string certificatePath = "certificate.pfx"; // path to PFX file
            string signaturePath = "signature.sig"; // path to signature
            string documentPath = "document.txt"; // path to document

            CreatePfx(certificatePath, certificatePassword);
            SignDocument(certificatePath, certificatePassword, documentPath, signaturePath);
            bool isVerified = VerifySignature(certificatePath, certificatePassword, documentPath, signaturePath);
            Console.WriteLine($"Signature verification result: {isVerified}");
        }

        public static void CreatePfx(string certificatePath, string certificatePassword)
        {
            var rsa = RSA.Create(2048);
            var request = new CertificateRequest("cn=Example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var cert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

            // Export to PFX
            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, certificatePassword);
            File.WriteAllBytes(certificatePath, pfxBytes);
        }

        public static void SignDocument(string certificatePath, string certificatePassword, string documentPath, string signaturePath)
        {

            // Load the certificate
            var certificate = new X509Certificate2(certificatePath, certificatePassword);

            // Read the document
            byte[] documentBytes = File.ReadAllBytes(documentPath);

            // Create a SHA256 hash of the document
            using SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(documentBytes);

            // Sign the hash using the private key of the certificate
            using RSA rsa = certificate.GetRSAPrivateKey();
            byte[] signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Save the signature to a file
            File.WriteAllBytes(signaturePath, signature);
            Console.WriteLine("Document signed successfully!");
        }

        public static bool VerifySignature(string certificatePath, string certificatePassword, string documentPath, string signaturePath)
        {
            try
            {
                // Load the certificate
                var certificate = new X509Certificate2(certificatePath, certificatePassword);

                // Read the document and signature
                byte[] documentBytes = File.ReadAllBytes(documentPath);
                byte[] signatureBytes = File.ReadAllBytes(signaturePath);

                // Create a SHA256 hash of the document
                using SHA256 sha256 = SHA256.Create();
                byte[] hash = sha256.ComputeHash(documentBytes);

                // Verify the signature using the public key of the certificate
                using RSA rsa = certificate.GetRSAPublicKey();
                bool isValid = rsa.VerifyHash(hash, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return isValid;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            return false;
        }
    }
}
