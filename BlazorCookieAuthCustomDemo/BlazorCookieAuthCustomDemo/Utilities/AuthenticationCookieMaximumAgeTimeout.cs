using Microsoft.AspNetCore.Authentication.Cookies;

namespace BlazorCookieAuthCustomDemo.Utilities
{
    public class AuthenticationCookieMaximumAgeTimeout : CookieAuthenticationEvents
    {
        public override Task SigningIn(CookieSigningInContext context)
        {
            // add an "ExpiresInTicks" string value to the authentication cookie, this is the current date time in ticks plus one day
            context.Properties.SetString("ExpiresInTicks", (DateTime.UtcNow.Ticks + TimeSpan.FromHours(8).Ticks).ToString());
            return base.SigningIn(context);
        }

        public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
        {
            // grab the "ExpiresInTicks" string value from the authentication cookie
            var expiresAtStringValue = context.Properties.GetString("ExpiresInTicks");

            // if there is no "ExpiresInTicks" value, reject the authentication request
            if (string.IsNullOrEmpty(expiresAtStringValue))
            {
                context.RejectPrincipal();
                return;
            }

            long expiresAtLongValue;

            // if the "ExpiresInTicks" value cannot be parsed to a long, reject the authentication request
            if (!long.TryParse(expiresAtStringValue, out expiresAtLongValue))
            {
                context.RejectPrincipal();
                return;
            }

            // if the "ExpiresInTicks" value is less than the current time, reject the authentication request
            if (DateTime.UtcNow.Ticks > expiresAtLongValue)
            {
                context.RejectPrincipal();
                return;
            }

            // otherwise, continue validation of the authentication cookie
            await base.ValidatePrincipal(context);
        }
    }
}
