using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TT.Core.Authorization
{
    public class TokenService
    {
        // token mekanizmasını neden kullanırız ? 
        // önce database imizde olan kullanıcıları kontrol mekanizmasından geçirip (email, password) kullanıcılarımızın içindense token üretiriz.
        private readonly IConfiguration configuration; // configuration dosyasından bilgi alacağımız için ekliyoruz.
        private readonly string _secretKey;
        private readonly string _issuer;
        private readonly string? _audience;

        public TokenService(IConfiguration _configuration, string secretKey, string issuer, string? audience)
        {
            configuration = _configuration;
            _secretKey = secretKey;
            _issuer = issuer;
            _audience = audience;
        }

        public string GenerateToken(string userId, string userEmail)
        {
            // Header
            // kullanacağımız projedeki configuration dosyasından alacağımız bilgiler için;
            var jwtSettings = configuration.GetSection("JwtSettings"); 
            var secretKey = jwtSettings["SecretKey"]; // bilgilerin şifrelenmesi bu key yapısına göre olur. minimum 16 karakter olmalı
            var issuer = jwtSettings["Issuer"]; // token ı oluşturan sunucu
            var audience = jwtSettings["Audience"]; // token ı kullanacak kişi, uygulama, site. örneğin bir sitenin kullanımına özel bir api projemiz varsa buraya yazarız.
            var expireMinutes = int.Parse(jwtSettings["ExpireMinutes"]); // api yi tüketme erişim süresi (dk)

            // Payload -> Claim
            var claims = new[] // her biri bir data tutar. new[] -> anonymous type.
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId), // token ın hangi kullanıcıya ait olduğunu belirtmek için kullanılır.
                new Claim(JwtRegisteredClaimNames.Email, userEmail), // token ın hangi email e ait olduğunu belirtmek için kullanılır. sub, email vs bu paketin kendi claimleri. biz de kendi claim imizi tanım layabiliriz.
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // token ları benzersiz yapan mekanizma (jti), her token için farklı bir jti değeri oluşturur.
                // new Claim("CompanyId", "110") // kendi claim lerimizi oluşturabiliriz.
            };
            // payload kısmında claim olarak roller de tutulabilir. örneğin bir kişiye sadece read only erişim verilebilir. veya belli başlara endpointlere
            // erişim sağlayabilir gibi...
            // payload kısmı önemli çünkü, diyelim api mize biri istek attı. controller lardan kimin istek attığına tokendaki payload içerisinden tüm bilgilerine erişebiliriz.

            // Signature için gerekli
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)); // imza için kullanılacak secretkey i tekrar encode ediyor (tekrar şifreliyor yani (byte a dönüştürerek)) daha gizli hale getiriyor.

            var signingCreds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256); // api isteklerini doğrulamada "Hash-based Message Authentication Code" algoritması ile SHA-256 hash fonksiyonunu birleştiren bir kriptografik yöntemdir.
                                                                                           // üç yapının (h.p.s) algoritmik olarak farklı bir şekilde karşımıza çıkmasını sağlayan bu algoritmadır (HmacSha256)
                                                                                           
            // Signature oluşturma (üç parçayı oluşturduğumuz yer)
            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expireMinutes),
                signingCredentials: signingCreds // token üretme işlemlerini bu kurala göre (signingCreds) yapmasını söylüyoruz. key ve key de kullacağımız algoritma (HmacSha256) önemli.
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public bool IsValidToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_secretKey);

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = true, // Program.cs ile uyumlu
                    ValidateAudience = false, // Program.cs ile uyumlu
                    ValidateLifetime = true, // Süre dolmuş mu kontrolü
                    ValidateIssuerSigningKey = true, // İmza anahtarının doğruluğu kontrolü
                    ValidIssuer = _issuer, // Geçerli issuer
                    ValidAudience = _audience, // Geçerli audience
                    IssuerSigningKey = new SymmetricSecurityKey(key), // İmzalama anahtarı
                    ClockSkew = TimeSpan.FromMinutes(5) // Program.cs ile aynı tolerans süresi
                }, out SecurityToken validatedToken);

                return true; // Token geçerli
            }
            catch (Exception)
            {
                // Hata durumunda false döner, hatayı loglayabilirsiniz
                return false;
            }
        }

    }

    // JWT ;
    // Header - başlık
        // token ın türü -> JWT
        // İmzalama (özetleme) algoritması HMAC SHA256
    // Payload - veri
        // token içerisinde taşınan veri, uygulama içerisinde ihtiyaç olunan verilerdir. (user bilgiler) json object olarak tutulur.
    // Signature - imza
        // header ve payload bilgilerini sırayla bir araya getirip, birleştirir ve bir imza oluşturur.
        // token ın güvenliğini sağlamayı ve değiştirilmeden kullanılmasını sağlar.

    // jwt ye benzer bir başka erişim sınırlama aracı api key lerdir. fakat token lar kadar güvenli ve kapsamlı sayılmazlar.
    // token lardan elde ettiğimiz bilgileri, api key lerden elde edemeyiz.
}
