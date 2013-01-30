using System;
using System.IO;
using System.IdentityModel.Protocols.WSTrust;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel.Security;
using System.ServiceModel;
using System.IdentityModel.Tokens;
using System.Xml;
using Thinktecture.IdentityModel.WSTrust;

namespace ADFSAuth
{
    class Program
    {
        static void Main()
        {
            //Setup the connection to ADFS
            var factory = new WSTrustChannelFactory(new WindowsWSTrustBinding(SecurityMode.TransportWithMessageCredential), new EndpointAddress("https://dcadfs.security.net/adfs/services/trust/13/windowsmixed"))
            {
                TrustVersion = TrustVersion.WSTrust13
            };

            //Setup the request object 
            var rst = new RequestSecurityToken
            {
                RequestType = RequestTypes.Issue,
                KeyType = KeyTypes.Bearer,
                AppliesTo = new EndpointReference("https://dcadfs.security.net/adfs/gav")
            };

            //Open a connection to ADFS and get a token for the logged in user
            var channel = factory.CreateChannel();
            var genericToken = channel.Issue(rst) as GenericXmlSecurityToken;

            if (genericToken != null)
            {
                //Setup the handlers needed to convert the generic token to a SAML Token
                var thumbPrintValidator = new ConfigurationBasedIssuerNameRegistry();
                thumbPrintValidator.ConfiguredTrustedIssuers.Add(new System.Collections.Generic.KeyValuePair<string, string>("4880bfd77c1a87f9c7256be9900f55ba09317cbb", "‎Certificate ThumbPrint"));

                var tokenHandlers = new SecurityTokenHandlerCollection(new SecurityTokenHandler[] { new SamlSecurityTokenHandler() });
                tokenHandlers.Configuration.AudienceRestriction = new AudienceRestriction() { AudienceMode = System.IdentityModel.Selectors.AudienceUriMode.Never };
                tokenHandlers.Configuration.IssuerNameRegistry = thumbPrintValidator;
                //Swap above line for this one to use the custom TrustedIssuerNameRegistry class below this gives you more flexability to customize the authentication of the issuer
                //tokenHandlers.Configuration.IssuerNameRegistry = thumbPrintValidator;

                //convert the generic security token to a saml token
                var samlToken = tokenHandlers.ReadToken(new XmlTextReader(new StringReader(genericToken.TokenXml.OuterXml)));

                //convert the saml token to a claims principal
                var claimsPrincipal = new ClaimsPrincipal(tokenHandlers.ValidateToken(samlToken).First());

                //Display token information
                Console.WriteLine("Name : " + claimsPrincipal.Identity.Name);
                Console.WriteLine("Auth Type : " + claimsPrincipal.Identity.AuthenticationType);
                Console.WriteLine("Is Authed : " + claimsPrincipal.Identity.IsAuthenticated);
                foreach (var c in claimsPrincipal.Claims)
                    Console.WriteLine(c.Type + " / " + c.Value);
                Console.ReadLine();
            }
        }

        //The token handler calls this to check the token is from a trusted issuer before converting it to a claims principal
        //In this case I authenticate this by checking the certificate name used to sign the token
        //TODO : Should probably do more than just check the certificate name. I think the relying party has a uniqe thumbprint in AD FS
        public class TrustedIssuerNameRegistry : IssuerNameRegistry
        {
            public override string GetIssuerName(SecurityToken securityToken)
            {
                var x509Token = securityToken as X509SecurityToken;
                if (x509Token != null && String.Equals(x509Token.Certificate.SubjectName.Name, "CN=ADFS Signing - DCADFS.security.net"))
                    return x509Token.Certificate.SubjectName.Name;
                throw new SecurityTokenException("Untrusted issuer.");
            }
        }

    }
}
