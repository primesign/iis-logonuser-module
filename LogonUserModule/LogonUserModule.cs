using System;
using System.Web;
using System.Security.Principal;
using System.Linq;

namespace LogonUserModule
{
    public class LogonUserModule : IHttpModule
    {
        static string[] bannedHeaders = { "logon-user", "logon_user", "remote-user", "remote_user" };

        public void Dispose()
        {
        }

        public void Init(HttpApplication context)
        {
            context.PostAuthenticateRequest += new EventHandler(this.OnAuthorizeRequest);
        }

        public void OnAuthorizeRequest(object sender, EventArgs e)
        {
            HttpApplication application = (HttpApplication)sender;
            string[] allKeys = application.Request.Headers.AllKeys;
            // Remove potentially dangerous keys
            foreach (string header in allKeys)
            {
                if (bannedHeaders.Contains(header.ToLower())) {
                    application.Request.Headers.Remove(header);
                }
            }
            IIdentity id = HttpContext.Current.User.Identity;
            if (null != id) {
                application.Request.Headers.Set("logon-user", id.Name);
            }
        }
    }
}
