﻿using BELibrary.Core.Entity;
using BELibrary.DbContext;
using BELibrary.Entity;
using BELibrary.Utils;
using System.Linq;
using System.Web;
using BELibrary.Core.Utils;

namespace CinemaOnline.Handler
{
    public class CookiesManage
    {
        public static bool CheckLanguageCode()
        {
            var cookiesClientLangCode = HttpContext.Current.Request.Cookies.Get(CookiesKey.LangCode);
            return cookiesClientLangCode != null && LangCode.GetList().Any(x => x == cookiesClientLangCode.Value);
        }

        public static string GetLanguageCode()
        {
            return CheckLanguageCode() ? HttpContext.Current.Request.Cookies.Get(CookiesKey.LangCode)?.Value : LangCode.Default;
        }

        public static bool Logined()
        {
            var cookiesClient = HttpContext.Current.Request.Cookies.Get(CookiesKey.Client);
            if (cookiesClient != null)
            {
                var decodeCookie = CryptorEngine.Decrypt(cookiesClient.Value, true);

                var decodeCookies = decodeCookie.Split('|');

                var host = HttpContext.Current.Request.Url.Authority;

                if (!host.ToLower().Equals(decodeCookies[1].ToLower()))
                {
                    return false;
                }
                using (var workScope = new UnitOfWork(new CinemaOnlineDbContext()))
                {
                    var us = workScope.Users.GetAccountByUsername(decodeCookies[0]);
                    return us != null;
                }
            }
            else
            {
                return false;
            }
        }

        public static User GetUser()
        {
            var cookiesClient = HttpContext.Current.Request.Cookies.Get(CookiesKey.Client);
            if (cookiesClient != null)
            {
                var decodeCookie = CryptorEngine.Decrypt(cookiesClient.Value, true);

                var decodeCookies = decodeCookie.Split('|');

                var host = HttpContext.Current.Request.Url.Authority;

                if (!host.ToLower().Equals(decodeCookies[1].ToLower()))
                {
                    return null;
                }
                using (var workScope = new UnitOfWork(new CinemaOnlineDbContext()))
                {
                    var us = workScope.Users.GetAccountByUsername(decodeCookies[0]);
                    return us;
                }
            }
            else
            {
                return null;
            }
        }

        //Xóa tất cả session
        public static void ClearAll()
        {
            HttpContext.Current.Session.RemoveAll();
        }
    }
}