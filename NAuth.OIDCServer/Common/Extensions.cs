using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IdentityServer4.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace NAuth.OIDCServer.Common
{
    /// <summary>
    /// 扩展帮助类
    /// </summary>
    public static class Extensions
    {

        /// <summary>
        /// 获取配文件信息
        /// </summary>
        /// <param name="app">IApplicationBuilder</param>
        /// <param name="configuration">IConfiguration</param>
        /// <param name="options">TokenConfig</param>
        /// <returns></returns>
        public static IApplicationBuilder GetAppsettingsJson(this IApplicationBuilder app, IConfiguration configuration,TokenConfig options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }
            var audienceConfig = configuration.GetSection("TokenConfig");
            var symmetricKeyAsBase64 = audienceConfig["Secret"];
            var keyByteArray = Encoding.ASCII.GetBytes(symmetricKeyAsBase64);
            var signingKey = new SymmetricSecurityKey(keyByteArray);
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            var tokenConfig = new TokenConfig
            {
                #region 初始化注入TokenConfig 到中间件
                Secret = audienceConfig["Secret"], //密钥
                Issuer = audienceConfig["Issuer"], //发行者
                Audience = audienceConfig["Audience"], //令牌的观众
                TokenType = audienceConfig["TokenType"], //表示令牌类型，该值大小写不敏感，必选项，可以是bearer类型或mac类型。
                Scope = audienceConfig["Scope"], //表示权限范围，如果与客户端申请的范围一致，此项可省略
                Subject = audienceConfig["Subject"], //主题
                ExpiresIn = Convert.ToInt32(audienceConfig["ExpiresIn"]), //表示过期时间，单位为秒。如果省略该参数，必须其他方式设置过期时间。
                ClientId = audienceConfig["ClientId"], //表示客户端的ID，必选项
                ResponseType = audienceConfig["ResponseType"], //表示授权类型，必选项，此处的值固定为"code"
                RedirectUri = audienceConfig["RedirectUri"],
                State = audienceConfig["State"], //表示客户端的当前状态，可以指定任意值，认证服务器会原封不动地返回这个值。
                SigningCredentials = signingCredentials
                #endregion
            };
            
            return app;
        }
        /// <summary>
        /// 注册 IResourceClient
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="services"></param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddResourceAndClient(this IIdentityServerBuilder builder, IServiceCollection services)
        {
            /*
             有三个注册的方法AddScoped、AddSingleton、AddTransient。这其中的三个选项（Singleton、Scoped和Transient）
             体现三种对服务对象生命周期的控制形式。
            Singleton：ServiceProvider创建的服务实例保存在作为根节点的ServiceProvider上，所有具有同一根节点的所有ServiceProvider提供的服务实例均是同一个对象。适合于单例模式。
            Scoped：ServiceProvider创建的服务实例由自己保存，所以同一个ServiceProvider对象提供的服务实例均是同一个对象。 可以简单的认为是每请求（Request）一个实例。
            Transient：针对每一次服务提供请求，ServiceProvider总是创建一个新的服务实例。 每次访问时被创建，适合轻量级的，无状态的服务。
             */
           
            return builder;
        }
    }
}
